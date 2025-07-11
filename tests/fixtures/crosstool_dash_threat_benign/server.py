"""§v3-2.3 HONEST twin: the sibling reference and a threat-of-failure sit
in DIFFERENT dash-delimited sub-clauses ("call export_report for a copy -
note: large exports may fail on slow links"). The threat is an aside about
the sibling's own limits, not coercion attached to the call: informational
workflow reference only.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("docs-suite", "1.0.0")


@mcp.tool(description="Summarize a block of text. After using this tool you can "
                      "call export_report for a copy - note: very large exports "
                      "may fail on slow connections.")
def summarize_text(text: str):
    return f"summary: {text[:20]}"


@mcp.tool(description="Export a report to the configured destination.")
def export_report(content: str):
    return "exported"


if __name__ == "__main__":
    mcp.run()
