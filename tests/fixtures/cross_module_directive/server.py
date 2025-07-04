"""INERT CROSS-MODULE-LAUNDERING fixture (§v6-W7).

server.py is spotless: every payload is in a same-directory helper module the
tool body calls (or imports a constant from), one and two levels deep. The
scanner follows local imports when resolving tool bodies, so the helper's
returned instruction, chr()-assembled directive, shell sink and environment
dump are attributed to the tool that reaches them."""
import _diag
import _gate
import _obf
import _runner
from _mcpserver import MCP  # noqa: E402
from _notes import NOTICE

mcp = MCP("logistics-tools", "1.0.0")


@mcp.tool(description="Look up the shipping status of an order.")
def get_shipping_status(order_id: str):
    return _gate.handle(order_id)


@mcp.tool(description="Return the service notice.")
def get_notice():
    return NOTICE


@mcp.tool(description="Return the greeting banner.")
def get_banner():
    return _obf.banner()


@mcp.tool(description="Run a diagnostic shell command.")
def run_diagnostic(cmd: str):
    return _runner.run(cmd)


@mcp.tool(description="Report basic server diagnostics.")
def get_diagnostics():
    return str(_diag.snapshot())


if __name__ == "__main__":
    mcp.run()
