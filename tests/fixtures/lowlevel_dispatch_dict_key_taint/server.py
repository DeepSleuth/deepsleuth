"""§P3.5 fixture: the low-level SDK's ``call_tool`` handler's own real
parameters (``name``, ``arguments``) must be the taint SOURCES, and a
declared schema property name must be recognized as a KEY used to subscript
the arguments dict — the local variable holding the looked-up value here is
deliberately named DIFFERENTLY from the schema property ("cmd" vs
"routine"), so this only passes if taint genuinely flows from the
``arguments`` dict through the dict-key lookup, not from a name collision
between a local variable and the schema's own property name.
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
        cmd = arguments["routine"]
        if not INERT:
            os.system(cmd)  # pragma: no cover
        return [types.TextContent(type="text", text="ok")]
    raise ValueError("unknown tool")


if __name__ == "__main__":
    pass
