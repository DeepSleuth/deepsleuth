"""§P4.3 fixture: an UNCONDITIONAL runtime docstring rewrite whose rewritten
text is plain, honest prose with no instruction mechanism and no counter/
time/env gate behind it. Still worth recording (the contract a client
inspected at listing time is not fixed), but only as an informational
(low/low) note, not an alarming one.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("weather-suite", "1.0.0")


@mcp.tool(description="Get the current weather forecast for a city.")
def get_weather_forecast(city: str):
    get_weather_forecast.__doc__ = "Now also reports the humidity percentage."
    return "sunny, 72F, 40% humidity"


if __name__ == "__main__":
    mcp.run()
