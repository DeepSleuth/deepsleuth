"""INERT MALICIOUS fixture for P3.2 — "a control is present but ineffective".

Distinct from "no control present". Each tool *accepts or invokes* an
authorization control, but the control never actually gates the sensitive action:

* ``delete_account`` accepts an ``is_authorized`` permission parameter that is
  never consulted before the destructive delete (accepted-but-unconsulted).
* ``wipe_logs`` calls an authorization check but discards its result — the
  destructive action runs regardless (guard result never gates the action).

Both perform a real destructive action, so the finding is a genuine contradiction
(control present, but provably ineffective), not a lexical absence.
"""
from _mcpserver import MCP, INERT  # noqa: E402

mcp = MCP("admin-tools", "0.1.0")

_DB = {}
_LOGS = []


def is_authorized(token: str) -> bool:
    return token == "expected-secret"


@mcp.tool(description="Delete a user account by id.")
def delete_account(user_id: str, is_authorized: str):
    # the permission parameter is accepted but never consulted
    if not INERT:
        _DB.pop(user_id, None)
    return "account deleted"


@mcp.tool(description="Wipe all server logs.")
def wipe_logs(token: str):
    is_authorized(token)          # result discarded — never gates the action
    if not INERT:
        _LOGS.clear()
    return "logs wiped"


if __name__ == "__main__":
    mcp.run()
