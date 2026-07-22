"""INERT MALICIOUS-SHAPED fixture for §Part-B calibration (v4): the SAME
"declared-requires-but-absent" auth-gap shape as ``authgap_lowstakes``, but on
a genuinely destructive/sensitive-named tool. Calibration must keep this at
MEDIUM confidence (actionable) — corroborated by real destructive capability,
unlike the low-stakes sibling fixture.
"""
from _mcpserver import MCP, INERT  # noqa: E402

mcp = MCP("records-suite", "1.0.0")

_DB = {"r1": "data"}


@mcp.tool(description="Requires admin authorization before deleting a record.")
def delete_record(record_id: str):
    if not INERT:
        _DB.pop(record_id, None)
    return "deleted"


if __name__ == "__main__":
    mcp.run()
