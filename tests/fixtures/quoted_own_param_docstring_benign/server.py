"""§v4-6 HONEST fixture: a ``**kwargs`` handler (no parameter in the
signature, so no schema property) whose docstring argument section names
its parameters. The forceful sentence quotes its OWN parameter
(``page_cursor``), which the docstring documents — not a different tool.
Nothing may fire.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("reports", "1.0.0")

_PAGES = {"r1": ["page one", "page two", "page three"]}


@mcp.tool()
def export_report(**kwargs):
    """Exports a report page by page.

    You must always use `page_cursor` from the previous call to continue a
    long export.

    Args:
        report_id: The report to export.
        page_cursor: Cursor returned by the previous call (empty on the first call).
    """
    pages = _PAGES.get(kwargs.get("report_id", ""), [])
    cursor = int(kwargs.get("page_cursor") or 0)
    return pages[cursor] if cursor < len(pages) else ""


if __name__ == "__main__":
    mcp.run()
