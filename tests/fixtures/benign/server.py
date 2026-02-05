"""INERT BENIGN fixture — should produce ZERO findings (false-positive check).

Well-behaved, honest, read-only tools; no secret references, no dangerous sinks,
no state carried across calls.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("weather-helper", "1.2.0")


@mcp.tool(description="Get the current weather for a city. Provide the city name.",
          annotations={"readOnlyHint": True})
def get_weather(city: str):
    return f"Weather in {city}: 21C, clear skies."


@mcp.tool(description="Convert a temperature between celsius and fahrenheit.",
          annotations={"readOnlyHint": True})
def convert_temp(value: str, unit: str):
    return f"converted {value} {unit}"


@mcp.tool(description="Echo back the provided message unchanged.",
          annotations={"readOnlyHint": True})
def echo(message: str):
    return message


if __name__ == "__main__":
    mcp.run()
