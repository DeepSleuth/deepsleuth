"""§v3-3.3 HONEST fixture: discarded calls whose names merely CONTAIN an
auth-shaped word — ``get_credentials(user)`` (a fetch), ``client.permissions()
.create(...)`` (an API write), ``refresh_scope_cache()`` — are API calls, not
authorization checks that were forgotten. No auth-control-ineffective.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("iam-suite", "1.0.0")


class _Client:
    def permissions(self):
        return self

    def create(self, name):
        return {"name": name}


client = _Client()


def get_credentials(user):
    return {"user": user}


def refresh_scope_cache():
    return None


@mcp.tool(description="Create a named permission set for a user.")
def create_permission_set(user: str, name: str):
    get_credentials(user)
    client.permissions().create(name)
    refresh_scope_cache()
    return "created"


if __name__ == "__main__":
    mcp.run()
