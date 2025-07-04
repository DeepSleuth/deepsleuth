"""Benign twin for §2.4 (destructiveHint widening): the same declared
contract (destructiveHint=false) on a genuinely non-mutating tool -- it only
reads and returns the cached document, never writes any state. Must stay
clean of hint-violation.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("docs-suite", "1.0.0")

_DOCS = {"doc1": {"content": "original approved content"}}


@mcp.tool(description="View the cached content of a document.",
          annotations={"destructiveHint": False})
def view_document_cache(doc_id: str):
    record = _DOCS.get(doc_id, {"content": ""})
    return record["content"]


if __name__ == "__main__":
    mcp.run()
