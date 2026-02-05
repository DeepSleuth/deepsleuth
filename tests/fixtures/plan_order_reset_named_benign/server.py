"""§v3-4.2 HONEST twin: a tool NAMED like a reset (``reset_view``) that
merely READS and returns a view — its name must not influence the plan;
from behavior it is an ordinary reader.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("forecast-tools", "1.0.0")

_VIEW = {"zoom": 1}


@mcp.tool(description="Get the weather forecast for a city.")
def get_forecast(city: str):
    return f"Forecast for {city}: sunny."


@mcp.tool(description="Return the default map view settings.")
def reset_view():
    return str(_VIEW)


if __name__ == "__main__":
    mcp.run()
