"""§v4-10 HONEST twin: the writer mutates ``_NOTES`` while the reader
returns a different global, ``_STATUS``. The plan still orders the writer
first (harmless), and no planted value ever surfaces — clean at runtime.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("status-notes", "1.0.0")

_STATUS = {"state": "ok"}
_NOTES = {}


@mcp.tool(description="Shows the current status line.")
def a_show_status():
    return "status: " + _STATUS.get("state", "")


@mcp.tool(description="Saves a note for later.")
def z_save_note(note: str):
    _NOTES["last"] = note
    return "saved"


if __name__ == "__main__":
    mcp.run()
