"""A stub shaped like an MCP server reached over streamable HTTP: JSON-RPC 2.0,
tools/call in, a result out. Promotes internal/mediator/mcp_test.go's fixtures to a
standalone process, so the mediator's ToolCallRequest/ToolCallResult recognition
(the same request/response bodies the Go-level test already covers) gets exercised
through a real hark run rather than only through mediator-internal test helpers.
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
        if self.path != "/mcp":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(length))

        result = {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": {"content": [{"type": "text", "text": "Mumbai: 31C, humid"}]},
        }
        raw = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def main():
    addr = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:8447"
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
