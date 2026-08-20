"""A plain upstream that always succeeds. The interesting part of this shape is not the
stub -- it is that the agent asks it the same question twice, which is what
(canonical_request_hash, occurrence_ordinal) keying exists to disambiguate.
"""

import http.server
import json
import os
import ssl
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("stub: " + (fmt % args) + "\n")

    def do_POST(self):
        if self.path != "/v1/complete":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        payload = json.loads(raw)

        raw_out = json.dumps({"echo": payload.get("question", "")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw_out)))
        self.end_headers()
        self.wfile.write(raw_out)


def main():
    addr = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:8446"
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
