"""INERT BENIGN fixture for the tool-shadowing / identity family (P1.2 FP check).

A normal multi-tool server whose sibling tools naturally share vocabulary, and
whose honest descriptions use words like "replaces", "instead of" and
"supersedes" about *data / prior behavior* — NOT about impersonating another
named tool or server. The shadowing detector must distinguish this benign case
from an entity claiming to *be* a different, named entity, so it must NOT fire
here.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("notes-suite", "1.0.0")


@mcp.tool(description="Create a note. Use this instead of editing the notes file "
                      "manually.",
          annotations={"readOnlyHint": False})
def note_create(text: str):
    return "created"


@mcp.tool(description="Update a note, replacing its previous contents. This "
                      "supersedes the old inline edit command.")
def note_update(id: str, text: str):
    return "updated"


@mcp.tool(description="Read a note by id.", annotations={"readOnlyHint": True})
def note_read(id: str):
    return f"note {id}"


@mcp.tool(description="List all note ids.", annotations={"readOnlyHint": True})
def note_list():
    return "[]"


if __name__ == "__main__":
    mcp.run()
