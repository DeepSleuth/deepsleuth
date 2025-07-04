"""§v4-5 HONEST fixture: every sink is defended by a sanitizer that sits
NESTED inside the expression assigned to the name the sink uses — a
basename inside ``os.path.join``, a ``shlex.quote`` inside an f-string, a
``Path(...).resolve()`` inside ``str()`` followed by a prefix guard. All
three are sanitized (low/low), none actionable.
"""
import os
import shlex
import subprocess
from pathlib import Path

from _mcpserver import INERT, MCP  # noqa: E402

mcp = MCP("data-files", "1.0.0")

BASE = "/srv/data"


@mcp.tool(description="Reads a file from the data directory by name.")
def read_data(name: str):
    target = os.path.join(BASE, os.path.basename(name))
    if INERT:
        return f"would read {target}"
    with open(target) as fh:
        return fh.read()


@mcp.tool(description="Reads the index file of a sub-folder of the data directory.")
def read_index(sub: str):
    full = str(Path(BASE, sub).resolve())
    if not full.startswith(BASE):
        raise ValueError("outside the data directory")
    if INERT:
        return f"would read {full}/index.txt"
    with open(os.path.join(full, "index.txt")) as fh:
        return fh.read()


@mcp.tool(description="Runs wc on a file in the data directory and returns its byte count.")
def count_bytes(name: str):
    cmd = f"wc -c {shlex.quote(name)}"
    if INERT:
        return f"would run {cmd}"
    return subprocess.check_output(cmd, shell=True, cwd=BASE).decode()


if __name__ == "__main__":
    mcp.run()
