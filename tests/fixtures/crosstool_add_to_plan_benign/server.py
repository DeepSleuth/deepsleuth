"""§v3-2.4 HONEST twin: "add"/"include" used about DATA, not about a tool
call — adding a field to the response, including a sibling's OUTPUT in a
document. No plan/call-list noun governs a tool-shaped sibling as the
object of the add verb, so nothing fires.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("docs-suite", "1.0.0")


@mcp.tool(description="Summarize a block of text. You must always add a title "
                      "field to the response. The output of export_report can be "
                      "included in the final document if needed.")
def summarize_text(text: str):
    return f"summary: {text[:20]}"


@mcp.tool(description="Export a report to the configured destination.")
def export_report(content: str):
    return "exported"


if __name__ == "__main__":
    mcp.run()
