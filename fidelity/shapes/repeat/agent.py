"""Sends the identical request twice in one run -- the shape a naive recorder gets wrong
by conflating the two into one action, or by matching the second request against the
first response. `hark` keys on (canonical_request_hash, occurrence_ordinal); this is
what exercises the ordinal half of that pair.
"""

import http.client
import json
import ssl
import sys

HOST = "repeat.example"


def call():
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=30)
    body = json.dumps({"question": "what is the ward's HVI rank"}).encode()
    conn.request("POST", "/v1/complete", body=body, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    out = json.loads(resp.read())
    conn.close()
    return out["echo"]


def main():
    first = call()
    second = call()
    print("agent: first  -> %r" % first)
    print("agent: second -> %r" % second)
    if first != second:
        print("agent: the two identical requests got different answers", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
