"""Benign twin for §2.7 (low-level SDK dispatch): the SAME two-handler shape
(list_tools + call_tool dispatching by string-literal comparison), but the
"run" branch never reaches a dangerous sink -- it just looks up a fixed
in-memory table. Must stay clean of ast-taint.
"""
from _mcpserver import INERT  # noqa: E402


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

_ROUTINES = {"cleanup": "cache cleared", "report": "report generated"}


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
        result = _ROUTINES.get(routine, "unknown routine")
        return [types.TextContent(type="text", text=result)]
    raise ValueError("unknown tool")


if __name__ == "__main__":
    pass
