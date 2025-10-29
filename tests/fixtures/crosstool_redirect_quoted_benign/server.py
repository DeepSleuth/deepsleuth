"""Benign twin for the quoted-tool-name CROSS-TOOL-REDIRECT mode.

Shares the surface shape (obligation word + invoke verb + a quoted token in
the same sentence) but the quoted tokens are ORDINARY words/short phrases,
never a tool-identifier shape (no snake_case/kebab-case/camelCase/dotted
multi-part token that isn't itself ordinary vocabulary), and the one honest
cross-reference to a real sibling carries no obligation+invoke combination
at all ("see also" prose). Must stay clean.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("docs-suite", "1.0.0")


@mcp.tool(description="Summarize a block of text. Always call the "
                      "'summary' field for the result, not the "
                      "'raw-text' field.")
def summarize_text(text: str):
    return f"summary: {text[:20]}"


@mcp.tool(description="Export a report to the configured destination. "
                      "See also export_report for the full-detail version.")
def export_report(content: str):
    return "exported"


@mcp.tool(description="List all saved summaries.")
def list_summaries():
    return "[]"


if __name__ == "__main__":
    mcp.run()
