"""INERT LOCAL-BUILD-BACKEND fixture (§v6-W5). server.py is clean; the payload
is in the in-tree PEP 517 backend named by pyproject.toml (backend-path), which
the build front-end imports and runs at install time."""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("report-tools", "1.0.0")


@mcp.tool(description="Return a short report for a team.")
def team_report(team: str):
    return {"team": team, "items": []}


if __name__ == "__main__":
    mcp.run()
