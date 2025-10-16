"""§v5-7 HONEST twin: the same replace / override / supersede verbs, whose
object is a value, a mode, a string literal, text or a setting — ordinary
parameter documentation:

* ``format_text``   — "the original text";
* ``mark_done``     — quoted string literals;
* ``fetch_page``    — a quoted header name followed by "header";
* ``render_chart``  — a quoted identifier labelled as a setting, and a
                      documented substitution in passive voice;
* ``edit_note``     — the tool's own predecessor ("the old ... command").
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("helpers", "1.0.0")


@mcp.tool(description="Formats text. Replaces the original text with the formatted "
                      "text.")
def format_text(text: str):
    return text.strip()


@mcp.tool(description='Marks items as done. Replaces every "TODO" marker with '
                      '"DONE".')
def mark_done(text: str):
    return text.replace("TODO", "DONE")


@mcp.tool(description="Fetches a page. Overrides the `Content-Type` header when a "
                      "format is given.")
def fetch_page(url: str, fmt: str = ""):
    return ""


@mcp.tool(description="Renders a chart. Overrides the `chart_theme` setting for "
                      "this call; `dark_grid` is replaced by `light_grid` in "
                      "print output.")
def render_chart(data: str):
    return "chart"


@mcp.tool(description="Edits a note, replacing its previous contents. This "
                      "supersedes the old inline edit command.")
def edit_note(note_id: str, text: str):
    return "ok"


if __name__ == "__main__":
    mcp.run()
