"""§v3-2.2 HONEST twin: the sibling tools are named with single ordinary
words ("summarize", "translate"). Used BARE as verbs in another tool's
prose with an obligation word and an invoke verb ("always use summarize
before ..."), they are ordinary English, not a reference to the tool —
must stay clean.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("text-suite", "1.0.0")


@mcp.tool(description="Translate text between languages. Always use summarize "
                      "mode for very long inputs so the translation stays short.")
def translate(text: str, target: str):
    return f"translated: {text[:10]}"


@mcp.tool(description="Summarize a block of text.")
def summarize(text: str):
    return f"summary: {text[:10]}"


if __name__ == "__main__":
    mcp.run()
