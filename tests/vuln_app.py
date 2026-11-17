import re
import threading
import time
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

from tests.oob_state import HITS

OOB_RE = re.compile(r"(rho_\w+)\.")


def run_cmd(cmd: str) -> str:
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return (out.stdout or "") + (out.stderr or "")
    except Exception:
        return ""


def make_vuln_app() -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):
            pass

        def _read_body(self) -> str:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if not length:
                return ""
            return self.rfile.read(length).decode("utf-8", "replace")

        def _respond(self, body: str, code: int = 200):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _handle(self):
            body = self._read_body()
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query, keep_blank_values=True)

            def param(key: str) -> str:
                if key in qs:
                    return unquote_plus(qs[key][0])
                ctype = self.headers.get("Content-Type", "")
                if "json" in ctype:
                    import json
                    try:
                        obj = json.loads(body)
                        if isinstance(obj, dict) and key in obj:
                            return str(obj[key])
                    except (ValueError, TypeError):
                        return ""
                else:
                    for part in body.split("&"):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            if k == key:
                                return unquote_plus(v)
                return ""

            probe = "".join(param(k) for k in ("host", "name", "tpl", "arg", "cmd", "q"))
            for m in OOB_RE.finditer(probe):
                if m.group(1) not in HITS:
                    HITS.append(m.group(1))

            path = parsed.path
            if path == "/vuln/ping":
                out = run_cmd(f"ping -c 1 {param('host')}")
                self._respond(f"<html><body><pre>{out}</pre></body></html>")
            elif path == "/vuln/echo":
                out = run_cmd(f"echo hello {param('name')}")
                self._respond(f"<html><body><pre>{out}</pre></body></html>")
            elif path == "/vuln/eval-quote":
                out = run_cmd(f"echo '{param('arg')}'")
                self._respond(f"<html><body><pre>{out}</pre></body></html>")
            elif path == "/vuln/ssti":
                val = param("tpl")
                try:
                    import jinja2
                    env = jinja2.Environment()
                    out = env.from_string(val).render()
                except Exception as exc:
                    out = f"render error: {exc}"
                self._respond(f"<html><body><div>{out}</div></body></html>")
            elif path == "/vuln/ssti-sandbox":
                val = param("tpl")
                try:
                    import jinja2.sandbox
                    env = jinja2.sandbox.SandboxedEnvironment()
                    out = env.from_string(val).render()
                except Exception as exc:
                    out = f"render error: {exc}"
                self._respond(f"<html><body><div>{out}</div></body></html>")
            elif path == "/safe/template":
                self._respond(f"<html><body><div>{param('tpl')}</div></body></html>")
            elif path == "/safe":
                self._respond(f"<html><body>you typed: {param('q')}</body></html>")
            elif path == "/slow":
                time.sleep(8)
                self._respond("slow page")
            else:
                self._respond("not found", 404)

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
