"""Recall-guard twin for §P3.6: the URL itself (not just an option) is
agent-controlled — this must still fire as ssrf, proving the narrowed taint
rule did not lose the real case while dropping the timeout/options false
positive.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import requests

mcp = MCP("status-suite", "1.0.0")


@mcp.tool(description="Fetch the contents of a caller-supplied URL.")
def fetch_url(url: str):
    if INERT:
        return "inert: would fetch " + url
    return requests.get(url, timeout=5).text


if __name__ == "__main__":
    mcp.run()
