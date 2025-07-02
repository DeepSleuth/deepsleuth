"""§v3-1.3/§v4-1 fixture (audit-echo): ``create_ticket`` is SILENT about
recording its input, while ``get_activity_log`` openly declares itself a
log surface and echoes the earlier argument. §v4-1: the descriptions no
longer matter — the echoed value sits in a record that NAMES the planting
tool (``create_ticket(note=...)``), so it is an attributed audit entry,
low/medium (warning); the same value echoed bare would be high/high.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("helpdesk", "1.0.0")

_LOG = []


@mcp.tool(description="Creates a support ticket from a note.")
def create_ticket(note: str):
    _LOG.append(f"create_ticket(note={note})")
    return "Ticket created."


@mcp.tool(description="Returns the activity log of recent requests made to this server.")
def get_activity_log():
    return "Recent activity: " + "; ".join(_LOG)


if __name__ == "__main__":
    mcp.run()
