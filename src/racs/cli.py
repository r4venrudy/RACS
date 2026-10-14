"""Local single-process launcher. Runtime secrets live outside the checkout."""

import argparse
import os
import secrets
from contextlib import contextmanager
from pathlib import Path

import uvicorn

from racs.app import create_app
from racs.storage import Store


@contextmanager
def instance_lock(path):
    with path.open("a+b") as stream:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            if not stream.read(1):
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def main():
    parser = argparse.ArgumentParser(description="Start RACS on loopback only")
    parser.add_argument("--port", type=int, default=8765)
    default_root = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share")) / "RACS"
    parser.add_argument("--data-dir", type=Path, default=default_root)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    args.data_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    with instance_lock(args.data_dir / "instance.lock"):
        token_path = args.data_dir / "api-token"
        if not token_path.exists():
            fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(secrets.token_urlsafe(32))
        token = token_path.read_text().strip()
        store = Store(args.data_dir / "racs.sqlite3")
        print(f"RACS Step 1: http://127.0.0.1:{args.port}")
        print(f"Local API token file: {token_path} (keep private)")
        uvicorn.run(
            create_app(store, token, port=args.port),
            host="127.0.0.1",
            port=args.port,
            workers=1,
            proxy_headers=False,
            access_log=False,
            limit_concurrency=16,
            timeout_keep_alive=5,
        )


if __name__ == "__main__":
    main()
