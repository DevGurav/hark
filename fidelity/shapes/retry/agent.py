"""Retries a failed call with a short backoff -- the pattern every LLM SDK's retry
wrapper follows (tenacity, the Google/OpenAI clients), reduced to its essence: the same
logical request sent more than once, each attempt its own HTTP request on the wire.
"""

import http.client
import json
import ssl
import sys
import time

HOST = "retry.example"
MAX_ATTEMPTS = 3


def call():
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=30)
    conn.request("POST", "/v1/complete", body=b"{}", headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


def main():
    for attempt in range(1, MAX_ATTEMPTS + 1):
        status, body = call()
        print("agent: attempt %d -> status %d" % (attempt, status))
        if status == 200:
            print("agent: %s" % json.loads(body)["answer"])
            return 0
        time.sleep(0.2 * attempt)

    print("agent: gave up after %d attempts" % MAX_ATTEMPTS, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
