"""A streaming upstream: one SSE response, flushed as separate chunks.

The property this shape exists to exercise is boundaries, not bytes -- see
internal/mediator/stream_test.go, which this promotes from a Go-internal fixture to a
standalone process a real agent can be pointed at.
"""

import http.server
import os
import ssl
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

CHUNKS = ["token one", "token two", "token three, the last one"]
GAP_S = 0.05


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("stub: " + (fmt % args) + "\n")

    def do_POST(self):
        if self.path != "/v1/stream":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)  # drain the request body

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        # HTTP/1.1 chunked framing, by hand: real streaming APIs use exactly this, and
        # it is what lets each SSE event arrive as its own TCP-level flush rather than
        # being reassembled by connection-close framing.
        for chunk in CHUNKS:
            data = ("data: %s\n\n" % chunk).encode()
            self.wfile.write(("%x\r\n" % len(data)).encode() + data + b"\r\n")
            self.wfile.flush()
            time.sleep(GAP_S)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


def main():
    addr = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:8444"
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
