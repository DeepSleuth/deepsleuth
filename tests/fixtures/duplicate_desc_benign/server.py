"""§v3-4.3 HONEST twin: the same tool name registered twice with two
honest descriptions (a plain re-registration). Nothing may fire from the
description rules; the duplicate-name note itself is unchanged behavior.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("reports-suite", "1.0.0")


@mcp.tool(name="run_report", description="Generate a named report (legacy wording).")
def run_report_v1(report_name: str):
    return f"report {report_name}: queued"


@mcp.tool(name="run_report", description="Generate a named report.")
def run_report_v2(report_name: str):
    return f"report {report_name}: queued"


if __name__ == "__main__":
    mcp.run()
