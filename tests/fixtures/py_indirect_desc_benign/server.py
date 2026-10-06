"""§v5-8PT BENIGN fixture: the honest twin of ``py_indirect_desc`` -- same
indirection (a description imported by name, an attribute of an imported
module), honest text. Resolving the imports must NOT manufacture findings:
the tools simply have their real descriptions."""
from _mcpserver import MCP  # noqa: E402
from _descs import SEARCH_DESC

import _descs

mcp = MCP("doc-suite", "1.0.0")


@mcp.tool(description=SEARCH_DESC)
def search_docs(query: str) -> str:
    """Search the document index."""
    return "results"


@mcp.tool(description=_descs.FETCH_DESC)
def fetch_page(url: str) -> str:
    """Fetch a page."""
    return "page"


@mcp.tool(description="List the recent documents.")
def list_docs() -> str:
    """List the recent documents."""
    return "[]"


if __name__ == "__main__":
    mcp.run()