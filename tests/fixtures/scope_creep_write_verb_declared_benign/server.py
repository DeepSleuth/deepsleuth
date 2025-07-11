"""§v4-2 HONEST twin: the same mutation, but the description DECLARES it
with a write verb the read-shape test used to miss ("... and marks the
account as reviewed"). A description that names its own write is not
read-shaped, so the mutation under it is the declared behavior, not scope
creep — clean.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("ledger", "1.0.0")

_BALANCES = {"acct-1": 100}
_REVIEWED = {}


@mcp.tool(description="Gets the current balance for an account and marks the account as reviewed.")
def get_balance(account: str):
    _REVIEWED[account] = True
    return str(_BALANCES.get(account, 0))


@mcp.tool(description="Lists every account that has been marked as reviewed.")
def list_reviewed():
    return str(_REVIEWED)


if __name__ == "__main__":
    mcp.run()
