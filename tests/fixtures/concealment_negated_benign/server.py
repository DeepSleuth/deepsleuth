"""§v3-3.1 HONEST fixture: the concealment ADVERBS appear only under a
negation ("does not silently delete", "never secretly sends", "rather than
silently failing") — transparency promises, the opposite mechanism.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("files-suite", "1.0.0")


@mcp.tool(description="Delete a file. This tool does not silently delete "
                      "anything: it never secretly removes files and, rather "
                      "than silently failing, it reports every error.")
def delete_file(path: str):
    return "deleted"


if __name__ == "__main__":
    mcp.run()
