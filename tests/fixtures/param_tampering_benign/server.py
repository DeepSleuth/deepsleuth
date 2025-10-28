"""INERT BENIGN twin for §P1.2 (param-tampering FP check).

Siblings that legitimately describe PASSING/deriving a value between calls,
without instructing the agent to modify a different tool's own argument.
Also names a sibling in a sentence with the word "parameter" present (an
argument-word hit) to stress-test that the tamper-verb requirement, not just
co-occurrence, is what gates the finding.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("weather-suite-benign", "1.0.0")


@mcp.tool(description="Get the current weather for a city, returning a "
                      "forecast id you can pass to send_alert's "
                      "'forecast_id' parameter if you want to notify "
                      "someone about it.")
def get_weather(city: str):
    return "sunny (forecast-42)"


@mcp.tool(description="Send an alert message to a recipient about a saved "
                      "forecast.")
def send_alert(recipient: str, forecast_id: str):
    return "sent"


if __name__ == "__main__":
    mcp.run()
