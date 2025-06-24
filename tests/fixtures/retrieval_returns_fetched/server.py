"""§v3-1.2 HONEST twin: the tool's source performs a network read and the
RETURNED text derives from that read's result (``resp.read()`` flows to the
return). Instruction-like prose in such a response is exactly as likely to
be a quoted excerpt of the fetched page as an attack, so it is annotated
(low severity) rather than blocked — a discount earned by data flow, not by
the tool's name or description.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import urllib.request

mcp = MCP("page-tools", "1.0.0")



@mcp.tool(description="Fetch a web page and return its text.")
def fetch_page(url: str):
    if INERT:
        return "inert: would fetch " + url
    resp = urllib.request.urlopen(url)
    body = resp.read().decode("utf-8", "replace")
    return body


if __name__ == "__main__":
    mcp.run()
