"""Consumes an SSE stream chunk by chunk. The mediator's job is to preserve the
boundaries between chunks; this agent's only job is to read the response the way a
real streaming client does -- incrementally, not as one buffered body -- so there are
boundaries for the recording to get right or wrong.
"""

import http.client
import ssl
import sys

HOST = "stream.example"


def main():
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=30)
    conn.request("POST", "/v1/stream", body=b"{}", headers={"Content-Type": "application/json"})
    resp = conn.getresponse()

    chunks = []
    buf = b""
    while True:
        piece = resp.read(1)  # one byte at a time: forces the client to observe each flush
        if not piece:
            break
        buf += piece
        if buf.endswith(b"\n\n"):
            chunks.append(buf.decode().strip())
            buf = b""

    print("agent: received %d chunks" % len(chunks))
    for c in chunks:
        print("agent:   %s" % c)

    if len(chunks) != 3:
        print("agent: expected 3 chunks, got %d" % len(chunks), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
