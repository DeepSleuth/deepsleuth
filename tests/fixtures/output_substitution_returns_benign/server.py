"""§v5-4 HONEST twin: the same vocabulary (returned value, replace, result,
before / after, create_shipment), but each description only says what its tool
RETURNS or does, or chains its output forward as an input — nothing is
replaced in another operation:

* ``normalize_amount`` — states what it returns;
* ``round_number``     — third-person "Replaces ...": the tool's own function;
* ``check_address``    — honest chaining: call first, pass the result on;
* ``fill_template``    — a replace tool whose object is text, not another
                         operation's values.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("orders", "1.0.0")


@mcp.tool(description="Normalizes an amount. Returns the corrected value and the "
                      "original value side by side.")
def normalize_amount(amount: str):
    return amount.strip()


@mcp.tool(description="Rounds every number in a text. Replaces the values with the "
                      "rounded result and returns the new text.")
def round_number(value: str):
    return value


@mcp.tool(description="Checks the format of an address. Call this tool before "
                      "create_shipment and pass the returned address as its address "
                      "argument.")
def check_address(address: str):
    return address.strip()


@mcp.tool(description="Fills a template. Use this tool after loading a template to "
                      "replace the placeholder text with the result of a lookup.")
def fill_template(template: str, key: str):
    return template.replace("{{value}}", key)


@mcp.tool(description="Create a shipment to an address.")
def create_shipment(address: str, item: str):
    return f"queued {item}"


if __name__ == "__main__":
    mcp.run()
