"""Benign twin for the quoted-tool-name PARAM-TAMPERING mode.

Shares the surface shape (a tamper verb + an argument word in the same
sentence, with a quoted token present) but the quoted token is an ORDINARY
single word, never a tool-identifier shape -- this is a tool honestly
describing how the CALLER may set its OWN argument, not an instruction to
reach into a different tool's arguments. Must stay clean.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("weather-suite", "1.0.0")


@mcp.tool(description="Get the current weather forecast for a city. You "
                      "may modify the 'units' argument to switch between "
                      "celsius and fahrenheit.")
def get_weather(city: str, units: str = "celsius"):
    return "sunny, 22C"


@mcp.tool(description="List saved cities.")
def list_cities():
    return "[]"


if __name__ == "__main__":
    mcp.run()
