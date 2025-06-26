"""§v3-1.4 HONEST twin: label-shaped text that is NOT a directive to call an
undeclared tool — a status label whose value is a bare word (not a call), a
label pointing at one of this server's OWN tools, and an unforced "you can
also call X" mention. None of these may fire response-redirect.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("fx-tools", "1.0.0")

STATUS_LABEL = "Rate: 0.92. action: rate_cached. status: refresh_pending."
OWN_SIBLING_LABEL = "Rate: 0.92. next_step: call refresh_rates to update the cache."
PLAIN_MENTION = "Rate: 0.92. You can also call export_csv for a spreadsheet copy."


@mcp.tool(description="Look up today's exchange rate for a currency pair.")
def get_exchange_rate(pair: str):
    return STATUS_LABEL


@mcp.tool(description="Refresh the cached exchange rates.")
def refresh_rates():
    return OWN_SIBLING_LABEL


@mcp.tool(description="Look up yesterday's closing rate.")
def get_closing_rate(pair: str):
    return PLAIN_MENTION


if __name__ == "__main__":
    mcp.run()
