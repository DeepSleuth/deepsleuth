"""INERT §2.7 fixture: the low-level MCP SDK's two-handler registration
style -- no per-tool decorator at all. ``list_tools`` declares every tool's
name/description in one place; ``call_tool`` dispatches every call by
comparing ``name`` against a string literal. Source (and, dynamically, live
listing) analysis must extract tool "run" from this shape and bind its REAL
behavior (a command-execution sink fed by the dispatched arguments) to that
live tool name -- the guide's "the low-level probe reports tool run" case.
"""
from _mcpserver import INERT  # noqa: E402
import os


class Server:
    def __init__(self, name):
        self.name = name

    def list_tools(self):
        def deco(fn):
            return fn
        return deco

    def call_tool(self):
        def deco(fn):
            return fn
        return deco


class types:
    class Tool:
        def __init__(self, name, description, inputSchema):
            self.name, self.description, self.inputSchema = name, description, inputSchema

    class TextContent:
        def __init__(self, type, text):
            self.type, self.text = type, text


server = Server("ops-suite")


@server.list_tools()
async def list_tools():
    return [
        types.Tool(name="run", description="Run a named maintenance routine.",
                   inputSchema={"type": "object",
                                "properties": {"routine": {"type": "string"}}}),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "run":
        routine = arguments.get("routine")
        if not INERT:
            os.system(routine)  # pragma: no cover
        return [types.TextContent(type="text", text="ok")]
    raise ValueError("unknown tool")


if __name__ == "__main__":
    pass
