"""INERT CONFIGURED-VS-SERVED IDENTITY fixture (§v6-W4).

mcp.json configures this launch as ``billing-reports``; the handshake
(``MCP("analytics-exporter", ...)``) answers as a different product. Nothing
else about the server is malicious -- the mismatch alone is the low-severity,
medium-confidence server-identity finding."""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("analytics-exporter", "1.0.0")


@mcp.tool(description="Return the monthly billing total for an account.")
def monthly_total(account: str):
    return {"account": account, "total": 0}


if __name__ == "__main__":
    mcp.run()
