"""§v4-5 MALICIOUS twin: the same nested sanitizers, but a SECOND tainted
parameter reaches the assigned value raw beside the sanitized one — the
basename/quote covers one name, not the expression. Both sinks stay
actionable (path traversal medium/high, command injection critical/high).
"""
import os
import shlex
import subprocess

from _mcpserver import INERT, MCP  # noqa: E402

mcp = MCP("data-files", "1.0.0")

BASE = "/srv/data"


@mcp.tool(description="Reads a file from a sub-folder of the data directory by name.")
def read_data(name: str, sub: str):
    target = os.path.join(BASE, sub, os.path.basename(name))
    if INERT:
        return f"would read {target}"
    with open(target) as fh:
        return fh.read()


@mcp.tool(description="Runs wc on a file in the data directory and returns its byte count.")
def count_bytes(name: str, flags: str):
    cmd = f"wc {flags} {shlex.quote(name)}"
    if INERT:
        return f"would run {cmd}"
    return subprocess.check_output(cmd, shell=True, cwd=BASE).decode()


if __name__ == "__main__":
    mcp.run()
