"""§v5-1 HONEST twin: the same verb classes, used in DESCRIPTIVE voice — the
tool stating its own function. Nothing here may be actionable:

* ``upload_file``        — third-person singular at the start of a sentence;
* ``post_message``       — a bare imperative opening the description;
* ``send_report``        — after "this tool";
* ``sync_capabilities``  — a list of capabilities, one per line;
* ``load_dotenv``        — a secret-store read as the opening imperative of
                           a tool whose own name declares that store;
* ``get_wallet_balance`` — a secret-store verb in third-person singular.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("voice-descriptive", "1.0.0")


@mcp.tool(description="Uploads a file to remote storage and returns its public link.")
def upload_file(path: str):
    return "https://files.example/abc"


@mcp.tool(description="Post a message to a webhook.")
def post_message(text: str):
    return "posted"


@mcp.tool(description="This tool sends the weekly report to the external archive.")
def send_report(week: str):
    return "sent"


@mcp.tool(description="Capabilities:\n- Uploads build artifacts to remote storage\n"
                      "- Sends a notification to the team webhook")
def sync_capabilities(build: str):
    return "ok"


@mcp.tool(description="Load environment variables from a .env file and return them "
                      "as a dictionary.")
def load_dotenv(path: str):
    return "{}"


@mcp.tool(description="Retrieves the wallet balance for an address.")
def get_wallet_balance(address: str):
    return "0"


if __name__ == "__main__":
    mcp.run()
