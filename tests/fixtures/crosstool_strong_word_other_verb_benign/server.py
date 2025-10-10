"""§v5-3 HONEST twin: the same sibling, the same strong obligation words
and an invoke verb in every clause — but the strong word governs a
DIFFERENT verb (match, returns), is a predicate about a parameter
("is required when using ..."), or the sibling is only the provenance of a
value ("the id returned by ..."). Each sentence merely mentions the
sibling: informational workflow references, never actionable.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("texts", "1.0.0")

@mcp.tool(description="Summarizes a block of text. The layout must match the "
                      "format used by export_report.")
def summarize_text(text: str):
    return text[:60]


@mcp.tool(description="Counts the words of a text. Always returns the totals that "
                      "export_report produced when it was last run.")
def word_count(text: str):
    return str(len(text.split()))


@mcp.tool(description="Detects the language of a report. The report id is required "
                      "before calling export_report again. You must pass the id "
                      "returned by export_report after it was called.")
def detect_language(report_id: str):
    return "en"


@mcp.tool(description="Export a report to the configured destination.")
def export_report(body: str):
    return f"report of {len(body)} characters"


if __name__ == "__main__":
    mcp.run()
