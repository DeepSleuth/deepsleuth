"""INERT BENIGN twin for §P1.6 (out-of-scope-parameter FP check).

Two ordinary domain-field collisions the rule must NOT fire on: a real-estate
tool's ``agent_name`` (a human sales agent, not the calling AI) and an
inference tool's ``model_name`` (which backend model to run -- a genuine,
USED domain input). Both share surface vocabulary with the caller-context
concept ("agent", "model", "name") but neither actually asks the calling
agent for information about itself -- the same "author" vs "auth" collision
class Phase 0 fixed for authorization tokens.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("domain-tools", "1.0.0")


@mcp.tool(description="Look up the sales agent assigned to a real-estate "
                      "listing.")
def get_listing_agent(listing_id: str, agent_name: str):
    return f"{agent_name} handles listing {listing_id}"


@mcp.tool(description="Run text generation against a chosen backend model.")
def run_inference(model_name: str, prompt: str):
    return f"{model_name} says: {prompt[::-1]}"


if __name__ == "__main__":
    mcp.run()
