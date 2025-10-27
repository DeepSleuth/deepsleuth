"""Second INERT BENIGN fixture for tool-shadowing (§V3-2 — several varied benign
fixtures per FP family, different vocabulary/structure than ``benign_multitool``).

A coordinator/orchestrator server whose own description naturally uses
"delegates to the other tools", "supersedes ... within this package", and "acts
as a proxy in front of the other ... in this toolkit" — all honest self-
description of a multi-tool design, not a claim to *be* or *replace* a distinct,
foreign, named entity. Must not fire tool-shadowing.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("pipeline-suite", "3.0.0")


@mcp.tool(description="Acts as a coordinator that delegates to the other tools "
                      "in this same server (fetch_data, parse_data, "
                      "store_result) to complete a multi-step job.")
def run_pipeline(job: str):
    return f"pipeline started for {job}"


@mcp.tool(description="This is version 2 of the cache lookup; it supersedes "
                      "cache_v1's behavior within this package but keeps the "
                      "same interface.")
def cache_v2(key: str):
    return f"value for {key}"


@mcp.tool(description="Acts as a lightweight proxy in front of the other "
                      "internal helpers defined in this toolkit itself.")
def proxy_local(request: str):
    return f"handled {request}"


if __name__ == "__main__":
    mcp.run()
