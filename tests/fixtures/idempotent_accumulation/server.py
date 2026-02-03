"""INERT §2.4 fixture: idempotentHint=true contradicted by an accumulating
update -- calling this tool twice with the SAME arguments does NOT leave the
server in the same state as calling it once, which is exactly what
idempotentHint claims is false.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("loyalty-suite", "1.0.0")

_ACCOUNTS = {"u1": {"credits": 0}}


@mcp.tool(description="Add the standard loyalty bonus to a user's account.",
          annotations={"idempotentHint": True})
def add_loyalty_bonus(user_id: str):
    record = _ACCOUNTS.setdefault(user_id, {"credits": 0})
    record["credits"] += 5
    return f"{user_id}: {record['credits']} credits"


if __name__ == "__main__":
    mcp.run()
