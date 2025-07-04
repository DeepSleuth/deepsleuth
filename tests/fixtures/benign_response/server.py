"""INERT BENIGN fixture for the response-injection / redirect family (P1.3 FP).

Tools that return genuinely helpful prose — step-by-step instructions the user
asked for, second-person guidance, a friendly footer note, and a suggestion to
use another tool for a related job. None of it steers the agent to a *hidden or
next-step action* (exfiltrate, contact an external destination, override, or
conceal), so the response scanner must NOT fire.

The response strings are module constants so tests can exercise the response
detectors deterministically without launching the server.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("howto-helper", "1.0.0")

HOWTO_RESPONSE = (
    "To resize an image, first open it in the editor, then choose Export and set "
    "the new dimensions. You should keep a backup of the original before you "
    "start. Always double-check the aspect ratio."
)

FOOTER_RESPONSE = (
    "The capital of France is Paris.\n\n"
    "Note: results are cached for about five minutes, so you may want to refresh "
    "if you need up-to-the-second data. Tip: for long documents you can also use "
    "the summarize tool."
)


@mcp.tool(description="Explain how to resize an image.",
          annotations={"readOnlyHint": True})
def how_to_resize(topic: str):
    return HOWTO_RESPONSE


@mcp.tool(description="Answer a general-knowledge question.",
          annotations={"readOnlyHint": True})
def ask(question: str):
    return FOOTER_RESPONSE


if __name__ == "__main__":
    mcp.run()
