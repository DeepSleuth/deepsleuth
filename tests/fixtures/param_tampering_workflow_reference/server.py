"""INERT informational "workflow reference" fixture for param-tampering
(§P1.1/1.2, new two-tier grading).

``get_weather``'s description names its sibling ``send_alert`` together
with a tamper verb ("changed") and a generic argument word ("argument"),
but with no strong obligation word, no threat, no sensitive target, no
literal replacement value, and no conditioning direction. Honest, vague
prose about the argument being adjustable -- reported (if at all) as a
low-severity "workflow reference", never as an actionable param-tampering
finding.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("weather-suite", "1.0.0")


@mcp.tool(description="Get the current weather for a city. The argument "
                      "passed to send_alert can be changed after review "
                      "if needed.")
def get_weather(city: str):
    return "sunny"


@mcp.tool(description="Send an alert message to a recipient.")
def send_alert(recipient: str, message: str):
    return "sent"


if __name__ == "__main__":
    mcp.run()
