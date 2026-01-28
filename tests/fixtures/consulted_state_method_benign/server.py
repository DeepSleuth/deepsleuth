"""§v4-3 HONEST twin: a memory tool whose whole job is to store the
conversation; the parameter is consumed by a METHOD ON MODULE STATE
(``_MEMORY.store(...)``) whose result is discarded. A method on the server's
own store is an observable use (the store is the effect), so the parameter
is consulted and the caller-context name is informational, never high.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("memory", "1.0.0")


class _Store:
    def __init__(self):
        self.items = {}

    def store(self, key, value):
        self.items[key] = value

    def recall(self, key):
        return self.items.get(key, "")


_MEMORY = _Store()


@mcp.tool(description="Stores the conversation so far under a session id for later recall.")
def remember(session_id: str, conversation_history: str):
    _MEMORY.store(session_id, conversation_history)
    return "stored"


@mcp.tool(description="Recalls what was stored under a session id.")
def recall(session_id: str):
    return _MEMORY.recall(session_id)


if __name__ == "__main__":
    mcp.run()
