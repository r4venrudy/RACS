"""SQLite transactions are the authority for grants and scan transitions."""

import hashlib
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from racs.scope import PolicyError, Scope

CHALLENGE_TTL = 600
GRANT_TTL = 86400
QUEUE_LIMIT = 32


class Store:
    def __init__(self, path: Path, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.transaction() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise RuntimeError("Unsupported database schema version")
            for statement in (
                """CREATE TABLE IF NOT EXISTS challenges (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, origin TEXT NOT NULL,
                    method TEXT NOT NULL, digest TEXT NOT NULL, expires REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0)""",
                """CREATE TABLE IF NOT EXISTS grants (
                    owner TEXT NOT NULL, origin TEXT NOT NULL, challenge_id TEXT NOT NULL,
                    expires REAL NOT NULL, PRIMARY KEY(owner, origin))""",
                """CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, origin TEXT NOT NULL,
                    grant_id TEXT NOT NULL, status TEXT NOT NULL,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL, detail TEXT NOT NULL)""",
                """CREATE TABLE IF NOT EXISTS throttle (
                    origin TEXT PRIMARY KEY, next_at REAL NOT NULL)""",
            ):
                db.execute(statement)
            db.execute("PRAGMA user_version=1")

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def issue(self, owner: str, scope: Scope, method: str) -> dict:
        if method not in ("dns", "https"):
            raise PolicyError("Unsupported verification method")
        token = "racs-v1=" + secrets.token_urlsafe(32)
        challenge_id = uuid.uuid4().hex
        expiry = self.clock() + CHALLENGE_TTL
        with self.transaction() as db:
            db.execute("DELETE FROM challenges WHERE expires<=?", (self.clock(),))
            if db.execute("SELECT count(*) FROM challenges").fetchone()[0] >= 128:
                raise PolicyError("Challenge capacity reached")
            db.execute("DELETE FROM challenges WHERE owner=? AND origin=?", (owner, scope.origin))
            db.execute(
                "INSERT INTO challenges(id,owner,origin,method,digest,expires) VALUES(?,?,?,?,?,?)",
                (
                    challenge_id,
                    owner,
                    scope.origin,
                    method,
                    hashlib.sha256(token.encode()).hexdigest(),
                    expiry,
                ),
            )
        return {
            "id": challenge_id,
            "origin": scope.origin,
            "method": method,
            "token": token,
            "expires_at": expiry,
            "location": f"_racs-verify.{scope.host}"
            if method == "dns"
            else scope.origin + "/.well-known/racs-verify.txt",
        }

    def begin_proof(self, owner: str, challenge_id: str) -> dict:
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM challenges WHERE id=? AND owner=?", (challenge_id, owner)
            ).fetchone()
            if not row or row["expires"] <= self.clock() or row["attempts"] >= 5:
                raise PolicyError("Challenge unavailable, expired, or exhausted")
            throttle = db.execute(
                "SELECT next_at FROM throttle WHERE origin=?", (row["origin"],)
            ).fetchone()
            if throttle and throttle[0] > self.clock():
                raise PolicyError("Wait before retrying this target")
            db.execute(
                "INSERT OR REPLACE INTO throttle VALUES(?,?)", (row["origin"], self.clock() + 10)
            )
            db.execute("UPDATE challenges SET attempts=attempts+1 WHERE id=?", (challenge_id,))
            return dict(row)

    def complete_proof(self, owner: str, challenge_id: str, records: list[str]) -> dict:
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM challenges WHERE id=? AND owner=?", (challenge_id, owner)
            ).fetchone()
            if not row or row["expires"] <= self.clock():
                raise PolicyError("Challenge unavailable or expired")
            if len(records) > 32 or not any(
                len(record) <= 4096
                and secrets.compare_digest(
                    hashlib.sha256(record.encode()).hexdigest(), row["digest"]
                )
                for record in records
            ):
                raise PolicyError("Ownership proof does not match")
            expiry = self.clock() + GRANT_TTL
            db.execute(
                "INSERT OR REPLACE INTO grants VALUES(?,?,?,?)",
                (owner, row["origin"], challenge_id, expiry),
            )
            db.execute("DELETE FROM challenges WHERE id=?", (challenge_id,))
            return {
                "origin": row["origin"],
                "expires_at": expiry,
                "scope": "exact HTTPS origin, port 443, root path",
            }

    def revoke(self, owner: str, scope: Scope):
        with self.transaction() as db:
            db.execute("DELETE FROM grants WHERE owner=? AND origin=?", (owner, scope.origin))
            db.execute("DELETE FROM challenges WHERE owner=? AND origin=?", (owner, scope.origin))
            db.execute(
                "UPDATE scans SET status='cancelled',updated_at=?,detail='Ownership revoked' WHERE owner=? AND origin=? AND status IN ('queued','running')",
                (self.clock(), owner, scope.origin),
            )

    def enqueue(self, owner: str, scope: Scope) -> dict:
        with self.transaction() as db:
            grant = db.execute(
                "SELECT * FROM grants WHERE owner=? AND origin=? AND expires>?",
                (owner, scope.origin, self.clock()),
            ).fetchone()
            if not grant:
                raise PolicyError("Current ownership verification is required")
            if (
                db.execute(
                    "SELECT count(*) FROM scans WHERE status IN ('queued','running')"
                ).fetchone()[0]
                >= QUEUE_LIMIT
            ):
                raise PolicyError("Scan queue is full")
            scan_id = uuid.uuid4().hex
            now = self.clock()
            db.execute(
                "INSERT INTO scans VALUES(?,?,?,?,?,?,?,?)",
                (
                    scan_id,
                    owner,
                    scope.origin,
                    grant["challenge_id"],
                    "queued",
                    now,
                    now,
                    "Awaiting worker",
                ),
            )
            return self._session(db, owner, scan_id)

    def _session(self, db, owner, scan_id):
        row = db.execute(
            "SELECT id,owner,origin,status,created_at,updated_at,detail FROM scans WHERE id=? AND owner=?",
            (scan_id, owner),
        ).fetchone()
        if not row:
            raise PolicyError("Scan not found")
        return dict(row)

    def session(self, owner, scan_id):
        with self.transaction() as db:
            self._expire(db)
            return self._session(db, owner, scan_id)

    def _expire(self, db):
        db.execute(
            """UPDATE scans SET status='cancelled',updated_at=?,detail='Ownership expired or replaced'
            WHERE status IN ('queued','running') AND NOT EXISTS (
            SELECT 1 FROM grants g WHERE g.owner=scans.owner AND g.origin=scans.origin
            AND g.challenge_id=scans.grant_id AND g.expires>?)""",
            (self.clock(), self.clock()),
        )

    def recover(self):
        with self.transaction() as db:
            db.execute(
                "UPDATE scans SET status='interrupted',updated_at=?,detail='Worker restarted; enqueue again after verification' WHERE status='running'",
                (self.clock(),),
            )
            self._expire(db)

    def claim(self) -> dict | None:
        with self.transaction() as db:
            self._expire(db)
            row = db.execute(
                "SELECT * FROM scans WHERE status='queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if not row:
                return None
            db.execute(
                "UPDATE scans SET status='running',updated_at=? WHERE id=?",
                (self.clock(), row["id"]),
            )
            return self._session(db, row["owner"], row["id"])

    def active(self, owner, scan_id):
        if self.session(owner, scan_id)["status"] != "running":
            raise PolicyError("Scan is no longer authorized or running")

    def finish(self, owner, scan_id, status, detail):
        if status not in ("not_performed", "completed", "failed", "cancelled"):
            raise PolicyError("Invalid terminal status")
        with self.transaction() as db:
            self._expire(db)
            db.execute(
                "UPDATE scans SET status=?,updated_at=?,detail=? WHERE id=? AND owner=? AND status='running'",
                (status, self.clock(), detail[:256], scan_id, owner),
            )

    def cancel(self, owner, scan_id):
        with self.transaction() as db:
            self._session(db, owner, scan_id)
            db.execute(
                "UPDATE scans SET status='cancelled',updated_at=?,detail='Cancelled by user' WHERE id=? AND owner=? AND status IN ('queued','running')",
                (self.clock(), scan_id, owner),
            )

    def purge(self, owner):
        with self.transaction() as db:
            for table in ("challenges", "grants", "scans"):
                db.execute(f"DELETE FROM {table} WHERE owner=?", (owner,))
