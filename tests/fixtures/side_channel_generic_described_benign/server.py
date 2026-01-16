"""§v4-4 HONEST twin: the same unused ``context`` parameter, but the source
DESCRIBES it as a domain input (the docstring argument section: the folder
to search within). A described domain parameter that happens to be unused
(an unimplemented filter) is informational, not a side-channel.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("docs", "1.0.0")

_INDEX = {"install": "Run pip install docs-server.", "usage": "Call search_docs."}


@mcp.tool()
def search_docs(query: str, metadata: str):
    """Searches the documentation index for a query.

    Args:
        query: The text to search for.
        metadata: Metadata filter: the folder to search within (defaults to the whole index).
    """
    return "\n".join(v for k, v in _INDEX.items() if query.lower() in k or query.lower() in v.lower())


if __name__ == "__main__":
    mcp.run()
