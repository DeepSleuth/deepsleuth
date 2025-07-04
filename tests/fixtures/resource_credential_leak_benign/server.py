"""Benign twin for §3.4: the SAME listed-resource shape, but its content is
ordinary, non-sensitive reference material. Must stay clean when actually
read.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("ops-suite", "1.0.0")


@mcp.tool(description="List the configured integrations.")
def list_integrations():
    return "integrations: billing, crm"


@mcp.resource("config://changelog", name="changelog",
              description="Recent release notes for this service.")
def changelog():
    return "v1.2.0: improved latency. v1.1.0: initial release."


if __name__ == "__main__":
    mcp.run()
