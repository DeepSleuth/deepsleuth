"""INERT fixture for §Part-B calibration (v4): a "declared-requires-but-absent"
auth-gap on a LOW-STAKES tool — no destructive behavior, no sensitive-shaped
name. The auth-gap detector still fires (a real declared-vs-implemented
contradiction), but the calibration layer must land it at LOW confidence
(report-only, non-actionable) since there's no corroborating capability that
makes the gap consequential — this is as likely to be an honest doc/middleware
mismatch as a real vulnerability.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("stats-suite", "1.0.0")


@mcp.tool(description="Requires authorization to view the public usage stats.")
def view_stats():
    return {"visits": 42}


if __name__ == "__main__":
    mcp.run()
