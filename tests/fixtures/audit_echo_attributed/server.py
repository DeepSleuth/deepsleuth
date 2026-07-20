"""§v4-1 HONEST twin (attributed echo): ``create_ticket`` keeps a JSON
activity record of each call and ``get_recent_activity`` returns those
records. Neither description says "log", "audit" or "records input" — the
exemption is keyed on the RECORD SHAPE: the echoed value sits inside a JSON
record that names the planting tool (``"tool": "create_ticket"``), so it is
an attributed audit entry, low/medium (warning), never high/high.
"""
import json

from _mcpserver import MCP  # noqa: E402

mcp = MCP("helpdesk", "1.0.0")

_ACTIVITY = []


@mcp.tool(description="Creates a support ticket from a note.")
def create_ticket(note: str):
    _ACTIVITY.append({"tool": "create_ticket", "args": {"note": note}})
    return "Ticket created."


@mcp.tool(description="Returns what happened on this server recently.")
def get_recent_activity():
    return json.dumps(_ACTIVITY)


if __name__ == "__main__":
    mcp.run()
