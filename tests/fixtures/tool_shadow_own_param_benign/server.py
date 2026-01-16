"""§v3-2.6 HONEST fixture: "override"/"replace" + a quoted token, where the
quoted token is one of this tool's OWN schema property names / enum values,
and the verb governs a parameter/option/mode word. The tool is describing
its own parameter semantics, not claiming to replace another entity.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("render-suite", "1.0.0")


@mcp.tool(description="Render a document. Setting 'mode' overrides the 'quality' "
                      "option; passing 'draft' replaces the default 'final' mode "
                      "for the current render only.")
def render_document(doc_id: str, mode: str = "final", quality: str = "high"):
    return "rendered"


if __name__ == "__main__":
    mcp.run()
