"""HONEST TWIN of gated_plan_depth (§v6 call-plan depth): the helper keeps a
usage counter with a threshold of 10 -- so the call plan goes deeper -- but
the response never changes. Plan depth may grow; findings must stay at zero."""
import _usage
from _mcpserver import MCP  # noqa: E402

mcp = MCP("forecast-tools", "1.0.0")


@mcp.tool(description="Get the weather forecast for a city.")
def get_forecast(city: str):
    return _usage.forecast(city)


if __name__ == "__main__":
    mcp.run()
