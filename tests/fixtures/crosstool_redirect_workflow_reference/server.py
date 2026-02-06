"""INERT informational "workflow reference" fixture (§P1.1, new two-tier
grading).

``summarize_text``'s description names its sibling ``export_report`` with
only a plain sequence word ("after") and an invoke verb ("call") -- no
strong obligation word (must/always/never/mandatory/required), no threat of
failure, no sensitive target, and not conditioned-on-the-sibling direction.
Under the new two-tier grading this is honest workflow advice: reported (if
at all) as a low-severity/low-confidence "workflow reference", never as an
actionable cross-tool-redirect finding.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("docs-suite", "1.0.0")


@mcp.tool(description="Summarize a block of text. After using this tool, "
                      "you may also call export_report for a formatted "
                      "copy of the result.")
def summarize_text(text: str):
    return f"summary: {text[:20]}"


@mcp.tool(description="Export a report to the configured destination.")
def export_report(content: str):
    return "exported"


@mcp.tool(description="List all saved summaries.")
def list_summaries():
    return "[]"


if __name__ == "__main__":
    mcp.run()
