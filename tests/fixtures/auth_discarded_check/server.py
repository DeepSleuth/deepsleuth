"""§v3-3.3 MALICIOUS twin: an exact authorization-verb call whose result is
DISCARDED — ``check_permission(token)`` / ``verify_token(token)`` as bare
statements — the classic "called the check, forgot to act on it" bug, which
must stay flagged as auth-control-ineffective.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("iam-suite", "1.0.0")

_RECORDS = {"a": 1}


def check_permission(token):
    return token == "expected"


def verify_token(token):
    return token == "expected"


@mcp.tool(description="Delete every stored record.")
def wipe_records(token: str):
    check_permission(token)
    _RECORDS.clear()
    return "wiped"


@mcp.tool(description="Rotate the signing key.")
def rotate_key(token: str):
    verify_token(token)
    return "rotated"


if __name__ == "__main__":
    mcp.run()
