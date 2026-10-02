"""Start the real Gunicorn factory on loopback; exercise the proxy contract."""
import http.client
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

from lightup.domain import DomainStore

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "smoke.db"
        store = DomainStore(db)
        store.bootstrap_operator("smoke@lightup.test", "Smoke", "offline-smoke-password")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = {**os.environ, "LIGHTUP_PUBLIC_ORIGIN": "https://lightup.example.test",
               "LIGHTUP_DB": str(db), "LIGHTUP_TRUSTED_PROXY_IP": "127.0.0.1"}
        proc = subprocess.Popen([sys.executable, "-m", "gunicorn",
            "--config", str(ROOT / "deploy/gunicorn.conf.py"),
            "--bind", f"127.0.0.1:{port}", "--workers", "1",
            "lightup.webapp.production:create_production_app()"], env=env)
        try:
            deadline = time.monotonic() + 15
            while True:
                if proc.poll() is not None:
                    raise RuntimeError("Gunicorn exited before readiness")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Gunicorn readiness timed out")
                    time.sleep(0.1)

            def request(method, path, data=None, **overrides):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                headers = {"Host": "lightup.example.test", "X-Forwarded-Proto": "https",
                           "Origin": "https://lightup.example.test",
                           "Content-Type": "application/x-www-form-urlencoded"}
                headers.update(overrides)
                try:
                    conn.request(method, path, urlencode(data) if data is not None else None, headers)
                    response = conn.getresponse()
                    result = response.status, dict(response.getheaders()), response.read()
                    return result
                finally:
                    conn.close()

            assert request("GET", "/login")[0] == 200
            assert request("GET", "/login", Host="evil.test")[0] == 403
            assert request("GET", "/login", **{"X-Forwarded-Proto": "http"})[0] == 403
            credentials = {"email": "smoke@lightup.test", "password": "offline-smoke-password"}
            assert request("POST", "/login", credentials, Origin="https://evil.test")[0] == 403
            status, headers, _ = request("POST", "/login", credentials)
            assert status == 303, status
            cookie = headers["Set-Cookie"].split(";")[0]
            assert "; Secure" in headers["Set-Cookie"]
            assert headers["Strict-Transport-Security"] == "max-age=31536000"
            assert request("GET", "/", Cookie=cookie)[0] == 200
            token = cookie.split("=", 1)[1]
            _, csrf = store.session_context(token)
            assert request("POST", "/logout", {"csrf": csrf}, Cookie=cookie)[0] == 303
            assert store.session_context(token) is None
            assert request("GET", "/", Cookie=cookie)[0] == 303
            print("Gunicorn proxy-boundary smoke OK: login, Secure cookie, guards, logout replay")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
