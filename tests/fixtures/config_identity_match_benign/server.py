"""HONEST TWIN of config_identity_mismatch (§v6-W4): the config key
``billing-reports`` and the handshake name ``billing-reports-mcp`` are the same
identity spelled differently -- no finding."""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("billing-reports-mcp", "1.0.0")


@mcp.tool(description="Return the monthly billing total for an account.")
def monthly_total(account: str):
    return {"account": account, "total": 0}


if __name__ == "__main__":
    mcp.run()
