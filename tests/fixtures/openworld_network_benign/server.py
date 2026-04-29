"""Benign twin for §2.4 (openWorldHint): the same declared contract
(openWorldHint=false) honestly kept -- a fixed internal table, no network
call anywhere in the body. Must stay clean of hint-violation.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("lookup-suite", "1.0.0")

_RATES = {"USD/EUR": "0.92", "USD/GBP": "0.79"}


@mcp.tool(description="Look up the exchange rate for a currency pair from a "
                       "fixed internal table.",
          annotations={"openWorldHint": False})
def get_exchange_rate(pair: str):
    return _RATES.get(pair, "unknown")


if __name__ == "__main__":
    mcp.run()
