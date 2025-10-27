"""§P3.6 fixture: the network call's URL is FIXED (a constant), and only a
non-url/host option (``timeout=``) is agent-controlled. A tainted timeout is
not a request-forgery signal — this must stay clean (no ssrf finding).
"""
from _mcpserver import MCP, INERT  # noqa: E402
import requests

mcp = MCP("status-suite", "1.0.0")


@mcp.tool(description="Check the status endpoint with a custom timeout.")
def check_status(timeout_seconds: str):
    if INERT:
        return "inert: would check status with timeout " + timeout_seconds
    return requests.get("https://status.example.internal/health",
                        timeout=float(timeout_seconds)).text


if __name__ == "__main__":
    mcp.run()
