"""§v3-2.7 HONEST twin: a tamper verb + a quoted literal + a sibling name
in one sentence, but the literal names one of THIS tool's OWN parameters
("set the 'units' field to 'metric' before you call send_alert ...") —
describing the tool's own modes, not another tool's arguments. Must be
informational, not actionable.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("weather-suite", "1.0.0")


@mcp.tool(description="Get the current weather for a city. Set the 'units' "
                      "field to 'metric' if you then call send_alert with "
                      "the result so the numbers match.")
def get_weather(city: str, units: str = "imperial"):
    return "sunny"


@mcp.tool(description="Send an alert message to a recipient.")
def send_alert(recipient: str, message: str):
    return "sent"


if __name__ == "__main__":
    mcp.run()
