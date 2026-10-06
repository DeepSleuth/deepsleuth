"""§v5-8PT MALICIOUS fixture: the Python mirror of ``js_indirect_desc`` --
every poisoned description is held INDIRECTLY, nothing at a registration site
is a plain string literal carrying the instruction. The resolver must follow
each shape to the text:

  search_docs  -- a constant imported by name (``from _descs import ...``)
  fetch_page   -- an attribute of an imported module (``_descs.FETCH``)
  list_docs    -- an honest literal, the control that must stay clean
"""
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