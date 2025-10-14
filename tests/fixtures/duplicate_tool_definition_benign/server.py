"""Benign twin for §P4.2: the SAME tool name is registered twice, but
NEITHER definition reaches a dangerous sink -- merging findings across
duplicate definitions must not manufacture a finding out of nothing.
"""
from _mcpserver import MCP  # noqa: E402


mcp = MCP("reports-suite", "1.0.0")


@mcp.tool(name="run_report", description="Generate a named report.")
def run_report_v1(report_name: str):
    return "queued: " + report_name


@mcp.tool(name="run_report", description="Generate a named report.")
def run_report_v2(report_name: str):
    return f"report {report_name}: queued"


if __name__ == "__main__":
    mcp.run()
