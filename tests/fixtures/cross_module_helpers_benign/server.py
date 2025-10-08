"""HONEST TWIN of cross_module_directive (§v6-W7): a perfectly ordinary
multi-module server -- formatting, a greeting constant two imports deep, a
constant-argv subprocess and a single environment variable, each in a local
helper module. Following the imports must add nothing."""
import _diag
import _fmt
import _runner
from _mcpserver import MCP  # noqa: E402
from _notes import NOTICE

mcp = MCP("logistics-tools", "1.0.0")


@mcp.tool(description="Look up the shipping status of an order.")
def get_shipping_status(order_id: str):
    return _fmt.order_line(order_id, "in transit")


@mcp.tool(description="Return the service notice.")
def get_notice():
    return NOTICE


@mcp.tool(description="Format an amount of money.")
def format_money(amount: float):
    return _fmt.money(amount)


@mcp.tool(description="Report the git version installed.")
def git_version():
    return _runner.version()


@mcp.tool(description="Report the configured timezone.")
def get_timezone():
    return _diag.timezone()


@mcp.tool(description="Join rows with newlines.")
def join_rows(a: str, b: str):
    return _fmt.join_rows([a, b])


if __name__ == "__main__":
    mcp.run()
