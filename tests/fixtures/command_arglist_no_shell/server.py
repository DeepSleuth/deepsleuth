"""§P3.2 fixture: the command is invoked as an argument-LIST call with no
shell involved (``subprocess.run([...], shell=False)``) — passing argv
elements as a list means there is no shell to reinterpret them, one of the
three accepted command sanitizers, independent of quoting/allow-listing.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import subprocess

mcp = MCP("ops-suite", "1.0.0")


@mcp.tool(description="Look up a DNS record for a hostname.")
def dns_lookup(hostname: str):
    if INERT:
        return "inert: would look up " + hostname
    return subprocess.run(["dig", hostname], shell=False, capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run()
