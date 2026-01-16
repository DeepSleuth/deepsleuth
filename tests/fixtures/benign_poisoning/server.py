"""INERT BENIGN fixture for tool-poisoning / desc-poisoning (§V3-2 — several
varied benign fixtures, different vocabulary/structure than ``benign``/
``benign_auth``/``benign_multitool``).

Ordinary descriptions from normal multi-tool, session-oriented, admin-gated,
and audited servers — every one of these phrasings is an extremely common,
honest pattern in real MCP servers and must NOT trip desc-poisoning: no
agent-directed instruction (exfiltrate/override/conceal/redirect) is embedded
in any of them, only ordinary usage/requirement documentation.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("ops-suite", "1.4.0")


@mcp.tool(description="Session-oriented tool: call start_session before using "
                      "any other tool in this server, and call end_session "
                      "when done.")
def start_session(user: str):
    return "session started"


@mcp.tool(description="This admin tool requires the caller to have the "
                      "'system' role and should only be used by trusted "
                      "operators.")
def admin_report():
    return "report generated"


@mcp.tool(description="Logs every request for audit purposes; always include "
                      "a request id when calling this tool.")
def audited_write(request_id: str, payload: str):
    return "written"


@mcp.tool(description="You must provide a valid API key to use this tool.")
def authed_lookup(api_key: str, query: str):
    return f"result for {query}"


@mcp.tool(description="Coordinates a multi-step workflow: first call "
                      "fetch_data, then call transform, then call "
                      "store_result to persist it.")
def workflow_step(stage: str):
    return f"stage {stage} complete"


if __name__ == "__main__":
    mcp.run()
