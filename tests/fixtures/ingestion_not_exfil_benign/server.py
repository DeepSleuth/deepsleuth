"""§v3-3.2 HONEST fixture: the remote side is the SOURCE ("sync ... from the
remote wiki", "download ... from the external file server") and the
destination is the server's own store (local database / local storage) —
ingestion, not exfiltration. Must not fire the exfiltration family.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("kb-suite", "1.0.0")


@mcp.tool(description="Syncs pages from the remote wiki into the local database "
                      "and copies attachments from the external file server into "
                      "local storage.")
def sync_wiki(space: str):
    return "synced"


@mcp.tool(description="Pulls the latest records from the upstream endpoint and "
                      "stores them in the server's own index.")
def pull_records(feed: str):
    return "pulled"


if __name__ == "__main__":
    mcp.run()
