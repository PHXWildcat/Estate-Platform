"""OCR sidecar: the smallest HTTP surface that runs Tesseract.

Stdlib only, no web framework — this process exists to keep a large C++ parser
off the documents service's dependency tree, so bringing a framework in here
would trade one dependency surface for another.

    POST /ocr     raw document bytes, Content-Type is the sniffed mime
                  -> 200 {"text": "..."}
    GET  /healthz -> 200 {"status":"ok"}

Every input is hostile by assumption: the bytes arrived as a user upload. So
they are written to a private temp file (never a path derived from anything the
caller sent), handed to tesseract as an argv element with no shell anywhere, and
bounded by a size cap and a wall-clock timeout. Failures answer 5xx with a fixed
message — the caller treats OCR failure as non-fatal, and a sidecar error body
would be one more piece of attacker-influenced text to handle.
"""

import json
import os
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Matches the documents service's own upload ceiling (10 MiB decoded).
MAX_BYTES = 10 * 1024 * 1024
# Bounded so one pathological page cannot pin the sidecar indefinitely; the
# client's own deadline is 30s, so this stays under it.
TIMEOUT_SECONDS = 25
PORT = int(os.environ.get("PORT", "8884"))


class Handler(BaseHTTPRequestHandler):
    # Silence the default stderr access log: it would record request lines for
    # documents whose very existence is user data.
    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        pass

    def _respond(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/ocr":
            self._respond(404, {"error": "not_found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._respond(400, {"error": "bad_request"})
            return
        if length <= 0 or length > MAX_BYTES:
            self._respond(413, {"error": "too_large"})
            return

        content = self.rfile.read(length)
        if len(content) != length:
            self._respond(400, {"error": "bad_request"})
            return

        # mkstemp gives a private path we chose; nothing the caller sent ever
        # reaches the filesystem as a name.
        fd, path = tempfile.mkstemp(prefix="ocr-", dir="/tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
            # No shell: argv list, fixed program, our own path.
            result = subprocess.run(
                ["tesseract", path, "stdout", "-l", "eng"],
                capture_output=True,
                timeout=TIMEOUT_SECONDS,
                check=False,
            )
            if result.returncode != 0:
                # Tesseract exits non-zero on an unreadable image, which is a
                # normal outcome for an arbitrary upload, not an error worth
                # surfacing. Empty text lets the caller store it un-indexed.
                self._respond(200, {"text": ""})
                return
            self._respond(200, {"text": result.stdout.decode("utf-8", errors="replace")})
        except subprocess.TimeoutExpired:
            self._respond(503, {"error": "timeout"})
        except Exception:  # noqa: BLE001 - never leak an internal message
            self._respond(500, {"error": "ocr_failed"})
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
