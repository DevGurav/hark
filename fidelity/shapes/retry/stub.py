"""An upstream that fails once, then succeeds -- the "same logical call, multiple HTTP
requests" case W5 found for real in UrbanHeat's Gemini traffic (503s and 429s against a
live free-tier quota). This is the hermetic version: no quota, no network, same shape.

State lives in the class, not the instance -- BaseHTTPRequestHandler makes a new instance
per request, and the stub process itself is what needs to remember it already failed once.
"""

import http.server
import json
import os
import ssl
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    attempts = 0

    def log_message(self, fmt, *args):
        sys.stderr.write("stub: " + (fmt % args) + "\n")

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        if self.path != "/v1/complete":
            self._send(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)

        Handler.attempts += 1
        if Handler.attempts == 1:
            self._send(503, {"error": "temporarily unavailable"})
            return
        self._send(200, {"answer": "the answer, on attempt %d" % Handler.attempts})


def main():
    addr = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:8445"
    host, port = addr.rsplit(":", 1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "..", "fidelity.pem")
    key = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "..", "..", "fidelity.key")
    ctx.load_cert_chain(cert, key)

    srv = http.server.ThreadingHTTPServer((host, int(port)), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    sys.stderr.write("stub: listening on %s\n" % addr)
    sys.stderr.flush()
    srv.serve_forever()


if __name__ == "__main__":
    main()
