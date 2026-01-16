"""§P3.5 precision fixture: the local variable happens to share its NAME
with the schema's declared property ("routine"), but it is assigned a fixed,
HARD-CODED literal — never read from the ``arguments`` dict at all. Seeding
taint from the handler's real params (``name``/``arguments``), not from the
schema's property names, means this bare name-collision no longer gets
mistaken for a genuine taint source; this must stay completely clean.
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
        types.Tool(name="run", description="Run a fixed maintenance routine.",
                   inputSchema={"type": "object",
                                "properties": {"routine": {"type": "string"}}}),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "run":
        routine = "cleanup"  # hard-coded, never read from `arguments`
        if not INERT:
            os.system(routine)  # pragma: no cover
        return [types.TextContent(type="text", text="ok")]
    raise ValueError("unknown tool")


if __name__ == "__main__":
    pass
