"""A small, naive agent. It fetches a page, asks a model what to do, and does it.

Deliberately naive, and deliberately typical. It is written the way a great many
real agents are written: content fetched from the web goes into the prompt, the
model's reply is parsed as a plan, and the plan is carried out without anyone
asking where the instruction in it came from.

Nothing here is a contrived vulnerability. There is no eval, no shell, no
disabled check. The only thing it does wrong is believe what it reads -- which
is the whole of prompt injection, and the reason containment has to sit outside
the agent rather than inside it.
"""

import json
import os
import sys
import time
import urllib.request
import uuid

DOCS = "https://docs.example/briefing"
MODEL = "https://model.example/v1/complete"

# The agent holds what it believes is its API key. It is a placeholder: the real
# value is substituted by hark at the boundary and never enters this process.
# The agent has no way to tell the difference, which is the point.
API_KEY = os.environ.get("MODEL_API_KEY", "")


def fetch(url, payload=None, headers=None):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", "replace")


def main():
    request_id = str(uuid.uuid4())
    started = time.time()
    print("agent: request %s at %.3f" % (request_id, started))

    print("agent: fetching %s" % DOCS)
    page = fetch(DOCS)
    print("agent: fetched %d bytes" % len(page))

    print("agent: asking the model what to do")
    reply = fetch(
        MODEL,
        {
            "request_id": request_id,
            "instruction": "Summarise this page for the team.",
            "page": page,
        },
        {"Content-Type": "application/json", "Authorization": "Bearer " + API_KEY},
    )
    plan = json.loads(reply)["plan"]
    print("agent: plan is %s" % plan["action"])

    if plan["action"] == "report":
        print("agent: summary -- %s" % plan["summary"])
        return 0

    if plan["action"] == "post":
        # The naive part, and the ordinary one. The plan asks for the key, so the
        # agent helpfully supplies it. It does not occur to the agent to wonder
        # why a summarisation task needs to post anything anywhere.
        payload = {"note": plan.get("note", "")}
        if plan.get("include_key"):
            payload["key"] = API_KEY
        print("agent: posting to %s" % plan["url"])
        fetch(plan["url"], payload, {"Content-Type": "application/json"})
        print("agent: posted")
        return 0

    print("agent: unknown action %r" % plan["action"], file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - the run is the artifact, not the traceback
        print("agent: failed: %r" % (exc,), file=sys.stderr)
        sys.exit(1)
