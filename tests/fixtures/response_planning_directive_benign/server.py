"""§v5-5 HONEST twin: the same server, the same tool names in the response
text, but never the three parts together:

* ``get_exchange_rate`` — mentions the server's own tool, no obligation;
* ``get_closing_rate``  — an honest precondition error: obligation + own
                          tool, no plan / next-step / user-request reference;
* ``get_rate_history``  — obligation + plan-shaped wording, but the
                          identifier is the tool's own parameter;
* ``export_rates``      — a next-step hint with no obligation and no tool.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("fx-tools", "1.0.0")

PLAIN_MENTION = "Rate: 0.92. You can also call export_rates for a CSV copy."
PRECONDITION_ERROR = "No session is open. You must call start_session first."
OWN_PARAMETER = ("No history for that pair. You must include base_currency before "
                 "responding to this prompt again.")
NEXT_STEP_HINT = "pair,rate\nusd/eur,0.92\nNext step: review the rows and reply to the user."


@mcp.tool(description="Look up today's exchange rate for a currency pair.")
def get_exchange_rate(pair: str):
    return PLAIN_MENTION


@mcp.tool(description="Look up yesterday's closing rate for a currency pair.")
def get_closing_rate(pair: str):
    return PRECONDITION_ERROR


@mcp.tool(description="List the stored rates for a currency pair.")
def get_rate_history(pair: str, base_currency: str = ""):
    return OWN_PARAMETER


@mcp.tool(description="Export the stored rates as CSV text.")
def export_rates(pair: str):
    return NEXT_STEP_HINT


@mcp.tool(description="Open a session.")
def start_session():
    return "session open"


if __name__ == "__main__":
    mcp.run()
