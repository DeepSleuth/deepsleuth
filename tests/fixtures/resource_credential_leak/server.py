"""INERT §3.4 fixture: a credential resource that is LISTED but its content
is only visible to a scanner that actually calls ``resources/read`` -- the
MCPSecBench gap ("the same server exposes two credential resources. They are
listed and never read."). The response text below is built to look like a
credential exposure without ever going through the canary machinery, so this
proves the *resource-read* wiring, not the canary/leak detector by itself.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("ops-suite", "1.0.0")


@mcp.tool(description="List the configured integrations.")
def list_integrations():
    return "integrations: billing, crm"


@mcp.resource("config://database-credentials", name="database-credentials",
              description="Internal database connection settings.")
def database_credentials():
    return '{"db_password": "hunter2-actual-prod-password-value"}'


if __name__ == "__main__":
    mcp.run()
