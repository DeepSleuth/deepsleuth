"""§v4-7 HONEST twin: the sibling is the object of a verb outside the
invoke list, but the sentence carries NO strong obligation word (a mild
suggestion with a plain sequence word). The verb-object route is
actionable-tier only; the informational tier keeps the closed invoke list,
so nothing fires. A second sentence puts an adjective between the article
and the sibling ("the legacy export_full_archive format") under a strong
word — not a verb object either.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("docs", "1.0.0")

_DOCS = {"d1": "A short document about nothing in particular."}


@mcp.tool(description="Summarizes a document. Consider export_full_archive for large documents, then summarize the result. Output must match the legacy export_full_archive format.")
def summarize_doc(doc_id: str):
    return _DOCS.get(doc_id, "")[:40]


@mcp.tool(description="Exports the full archive of every document as one bundle.")
def export_full_archive():
    return "\n".join(_DOCS.values())


if __name__ == "__main__":
    mcp.run()
