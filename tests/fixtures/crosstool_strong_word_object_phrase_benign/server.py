"""§v5-3 refinement, HONEST twin: the same sibling, a strong obligation word
and an invoke verb in every clause — but the sibling is never the object of
an invoke verb. It sits inside a prepositional phrase ("the value used IN
X", "is required BY X"), a participial phrase ("the id returned BY X") or a
relative clause ("what X produced"). Each sentence merely mentions the
sibling: informational workflow references, never actionable.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("texts", "1.0.0")

@mcp.tool(description="Summarizes a block of text. The title must match the "
                      "value used in export_report.")
def summarize_text(text: str):
    return text[:60]


@mcp.tool(description="Counts the words of a text. Always returns what "
                      "export_report produced when it was last run.")
def word_count(text: str):
    return str(len(text.split()))


@mcp.tool(description="Detects the language of a report. The id returned by "
                      "export_report must be used as the report id.")
def detect_language(report_id: str):
    return "en"


@mcp.tool(description="Counts the lines of a report. The section order is required "
                      "by export_report and must be set before it is used.")
def count_lines(report_id: str):
    return "0"


@mcp.tool(description="Export a report to the configured destination.")
def export_report(body: str):
    return f"report of {len(body)} characters"


if __name__ == "__main__":
    mcp.run()
