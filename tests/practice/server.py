"""Deliberately vulnerable synthetic practice target. Loopback only; never deploy."""

import argparse
import datetime
import html
import json
import sqlite3
import ssl
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def certificates(root):
    root.mkdir(parents=True, exist_ok=True)
    cert, key = root / "lab-cert.pem", root / "lab-key.pem"
    if cert.exists() and key.exists():
        return cert, key
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "racs-lab.localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("racs-lab.localhost")]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private, hashes.SHA256())
    )
    cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert, key


class Practice(BaseHTTPRequestHandler):
    root = Path(".")

    def log_message(self, *args):
        pass

    def do_GET(self):
        u = urlsplit(self.path)
        path = u.path
        q = parse_qs(u.query).get("q", ["1"])[0]
        status = 200
        kind = "text/html; charset=utf-8"
        headers = {}
        body = b""
        if path == "/.well-known/racs-verify.txt":
            proof = self.root / "proof.txt"
            body = proof.read_bytes() if proof.exists() else b"No challenge provisioned"
            kind = "text/plain"
        elif path.startswith("/juice/"):
            if path not in ("/juice/", "/juice/rest/products/search"):
                self.send_error(404)
                return
            endpoint = (
                "http://127.0.0.1:3000/"
                + path[len("/juice/") :]
                + ("?" + u.query if u.query else "")
            )
            try:

                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None

                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
                with opener.open(endpoint, timeout=3) as r:
                    body = r.read(262145)
                    kind = r.headers.get("Content-Type", "text/plain")
                    for k in (
                        "Content-Security-Policy",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                        "Strict-Transport-Security",
                    ):
                        if r.headers.get(k):
                            headers[k] = r.headers[k]
            except urllib.error.HTTPError as e:
                status = e.code
                body = e.read(4096)
                kind = e.headers.get("Content-Type", "text/plain")
        elif path == "/identity":
            token = self.headers.get("Authorization", "")
            ident = {
                "Bearer practice-alice-token": "alice",
                "Bearer practice-bob-token": "bob",
            }.get(token)
            status = 200 if ident else 401
            kind = "application/json"
            body = json.dumps({"id": ident}).encode()
        elif path in ("/vulnerable/object/alpha", "/safe/object/alpha", "/echo/object/alpha"):
            token = self.headers.get("Authorization", "")
            owner = token == "Bearer practice-alice-token"
            other = token == "Bearer practice-bob-token"
            if not owner and not other:
                status = 401
            elif path.startswith("/safe/") and not owner:
                status = 403
            kind = "application/json"
            obj = (
                {"id": "alpha", "private_test_marker": "synthetic-private-marker-49328"}
                if status == 200
                else {"error": "denied"}
            )
            if path.startswith("/echo/"):
                obj = {"id": "alpha"}
            body = json.dumps(obj).encode()
        elif path.endswith("/sqli"):
            kind = "application/json"
            with sqlite3.connect(":memory:") as db:
                db.executescript(
                    "CREATE TABLE items(id TEXT,name TEXT); INSERT INTO items VALUES('1','Synthetic item'),('2','Second fixture');"
                )
                try:
                    if path.startswith("/vulnerable/"):
                        rows = db.execute(
                            "SELECT id,name FROM items WHERE id='" + q + "'"
                        ).fetchall()
                    else:
                        rows = db.execute("SELECT id,name FROM items WHERE id=?", (q,)).fetchall()
                    body = json.dumps({"data": [{"id": r[0], "name": r[1]} for r in rows]}).encode()
                except sqlite3.Error:
                    status = 400
                    body = b'{"error":"Invalid query"}'
        elif path.endswith("/xss"):
            text = html.escape(q, quote=True) if path.startswith("/safe/") else q
            if path.startswith("/json/"):
                kind = "application/json"
                body = json.dumps({"value": q}).encode()
            else:
                body = (
                    "<!doctype html><html><title>Practice reflection</title><body><p>"
                    + text
                    + "</p></body></html>"
                ).encode()
            if path.startswith("/csp/"):
                headers["Content-Security-Policy"] = "default-src 'none'; script-src 'none'"
        elif path in ("/", "/vulnerable/headers", "/safe/headers"):
            body = b"<!doctype html><html><title>RACS practice target</title><body><h1>Synthetic practice target</h1><p>Do not deploy.</p></body></html>"
            if path.startswith("/safe/"):
                headers.update(
                    {
                        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                        "X-Content-Type-Options": "nosniff",
                        "Strict-Transport-Security": "max-age=31536000",
                    }
                )
        else:
            status = 404
            body = b"Not found"
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, required=True)
    args = p.parse_args()
    cert, key = certificates(args.root)
    Practice.root = args.root
    server = ThreadingHTTPServer(("127.0.0.1", 9443), Practice)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    print("Practice target listening on loopback 9443", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
