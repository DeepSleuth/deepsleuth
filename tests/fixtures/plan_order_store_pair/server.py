"""§v4-10 fixture (writer before reader, from behavior): ``z_save_note``
writes a module-level store and ``a_show_status`` returns it. The names
are chosen so alphabetical order would put the READER first; the call plan
must order the writer's calls before the reader's non-baseline calls using
``BehaviorFacts`` only, so the planted note is observable in the reader's
later response (a bare cross-call echo, high/high at runtime).
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("status-notes", "1.0.0")

_STORE = {}


@mcp.tool(description="Shows the current status line.")
def a_show_status():
    return "status: ok; last=" + _STORE.get("last", "")


@mcp.tool(description="Saves a note for later.")
def z_save_note(note: str):
    _STORE["last"] = note
    return "saved"


if __name__ == "__main__":
    mcp.run()
