"""§v3-2.1 HONEST twin: "at once" / "once more" are adverbial idioms, not a
condition on the sibling's use. "Fetch ... at once, then use export_report"
names a sibling with a sequence word and an invoke verb (informational
workflow reference), but must NOT be escalated by the conditions-on-other
direction test.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("docs-suite", "1.0.0")


@mcp.tool(description="Summarize a block of text. Fetches the summary and its "
                      "attachments all at once, then use export_report if you "
                      "want an archive; run it once more to refresh.")
def summarize_text(text: str):
    return f"summary: {text[:20]}"


@mcp.tool(description="Export a report to the configured destination.")
def export_report(content: str):
    return "exported"


if __name__ == "__main__":
    mcp.run()
