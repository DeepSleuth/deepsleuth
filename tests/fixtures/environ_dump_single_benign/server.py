"""HONEST TWIN of environ_dump_whole (§v6-W3): every environment access here is
SINGLE-VALUED or a consumer, never a whole-mapping disclosure -- one requested
variable, a membership test, a filtered ``APP_``-prefixed view, and the
environment handed to a child process. Must stay completely clean."""
import os
import subprocess

from _mcpserver import MCP  # noqa: E402

mcp = MCP("config-tools", "1.0.0")


@mcp.tool(description="Return the value of the single environment variable you name.")
def get_variable(name: str):
    return os.environ.get(name, "")


@mcp.tool(description="Check whether a feature flag is switched on.")
def flag_enabled(flag: str):
    return flag in os.environ


@mcp.tool(description="Return the application's own APP_-prefixed settings.")
def app_settings():
    return {k: v for k, v in os.environ.items() if k.startswith("APP_")}


@mcp.tool(description="Run the project build.")
def run_build(target: str = "all"):
    env = dict(os.environ)
    env["BUILD_TARGET"] = "release"
    done = subprocess.run(["make", "build"], env=env, capture_output=True, text=True)
    return done.stdout[-500:]


if __name__ == "__main__":
    mcp.run()
