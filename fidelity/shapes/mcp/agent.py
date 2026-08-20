"""Calls an MCP tool over streamable HTTP -- one JSON-RPC 2.0 tools/call request."""

import http.client
import json
import ssl
import sys

HOST = "mcp.example"


def main():
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=30)
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_weather", "arguments": {"city": "Mumbai"}},
        }
    ).encode()
    conn.request("POST", "/mcp", body=body, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    out = json.loads(resp.read())
    conn.close()

    text = out["result"]["content"][0]["text"]
    print("agent: tool result -> %s" % text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
