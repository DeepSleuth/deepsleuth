"""Benign twin for §2.2: an ordinary internal call counter (for metrics) that
NEVER touches __doc__ or any tool-registry-shaped metadata attribute. Must
stay clean of runtime-metadata-mutation.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("weather-suite", "1.0.0")

_calls = 0


@mcp.tool(description="Get the current weather forecast for a city.")
def get_weather_forecast(city: str):
    global _calls
    _calls += 1
    return "sunny, 72F"


if __name__ == "__main__":
    mcp.run()
