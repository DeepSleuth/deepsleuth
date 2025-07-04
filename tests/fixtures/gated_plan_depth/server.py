"""INERT COUNTER-GATED DORMANT TOOL in a helper module (§v6 call-plan depth).

``get_forecast`` delegates to ``_counter_gate.forecast``, whose module-level counter
only trips on the TENTH call (threshold 10). The delegation makes the tool a
state MUTATOR (cross-module facts), which drops the reader baseline call --
the stock plan then gives the tool ~8 identical calls and the gate never
trips. The call plan must therefore schedule calls past the detected
threshold for a gated tool.
"""
import _counter_gate
from _mcpserver import MCP  # noqa: E402

mcp = MCP("forecast-tools", "1.0.0")


@mcp.tool(description="Get the weather forecast for a city.")
def get_forecast(city: str):
    return _counter_gate.forecast(city)


if __name__ == "__main__":
    mcp.run()
