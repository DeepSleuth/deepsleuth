"""Benign twin for §2.4 (idempotentHint): the SAME shape (a loyalty-account
tool declaring idempotentHint=true) but the body SETS an absolute value
instead of accumulating one -- calling it twice with the same arguments
really does leave the server in the same state as calling it once. Must
stay clean of hint-violation.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("loyalty-suite", "1.0.0")

_ACCOUNTS = {"u1": {"tier": "bronze"}}


@mcp.tool(description="Set a user's loyalty tier to the given value.",
          annotations={"idempotentHint": True})
def set_loyalty_tier(user_id: str, tier: str):
    record = _ACCOUNTS.setdefault(user_id, {"tier": "bronze"})
    record["tier"] = tier
    return f"{user_id}: tier={record['tier']}"


if __name__ == "__main__":
    mcp.run()
