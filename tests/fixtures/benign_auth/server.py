"""INERT BENIGN fixture for the auth/audit family (P1.1 false-positive check).

Legitimately-designed tools that a *lexical* auth/audit-absence heuristic wrongly
flags, but that the contradiction principle leaves alone:

* ``delete_temp`` / ``reset_cache`` are honestly-declared, legitimately-
  unauthenticated *local* utilities. They mutate/delete for their stated purpose
  and carry no auth or logging — that is not a vulnerability, just an honest
  design. They must NOT produce a gate-tripping finding.
* ``purge`` DOES have an authorization control, and it is *effective* (the failing
  branch raises before the destructive action). The "control present but
  ineffective" detector (P3.2) must NOT fire on it.

Everything is guarded by INERT so nothing runs.
"""
from _mcpserver import MCP, INERT  # noqa: E402

mcp = MCP("file-utils", "1.0.0")

_CACHE = {}
_DB = {}


@mcp.tool(description="Clear the local temp cache directory.")
def clear_temp():
    # honest destructive utility, fixed path (no tainted input), no auth by design
    if not INERT:
        import shutil
        shutil.rmtree("/var/tmp/app-cache")
    return "cleared"


@mcp.tool(description="Reset the in-memory cache.")
def reset_cache():
    if not INERT:
        _CACHE.clear()
    return "cache reset"


def is_authorized(auth_token: str) -> bool:
    return auth_token == "expected-secret"


@mcp.tool(description="Purge a stored record. Requires a valid authorization token.")
def purge(record_id: str, auth_token: str):
    if not is_authorized(auth_token):          # effective guard: failing branch...
        raise PermissionError("unauthorized")  # ...halts before the destructive op
    if not INERT:
        _DB.pop(record_id, None)
    return "purged"


if __name__ == "__main__":
    mcp.run()
