"""§v3-3.4 HONEST fixture: the canonical path-guard idioms, each correctly
defending a tainted path or command — a prefix test against ``BASE +
os.sep``, against an f-string of the base, ``os.path.commonpath`` compared
with the base, ``Path(...).is_relative_to(BASE)``, and ``os.path.basename``
/ ``shlex.quote`` NESTED inside the sink's own argument expression. Every
sink must resolve as sanitized (informational), none actionable.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import os
import shlex
from pathlib import Path

mcp = MCP("docs-suite", "1.0.0")

_BASE_DIR = "/srv/docs"
_BASE_PATH = Path("/srv/docs")


@mcp.tool(description="Read a document (prefix test against BASE + os.sep).")
def read_sep(relative_path: str):
    real = os.path.realpath(os.path.join(_BASE_DIR, relative_path))
    if not real.startswith(_BASE_DIR + os.sep):
        return "error: outside docs"
    with open(real) as f:
        return f.read()


@mcp.tool(description="Read a document (prefix test against an f-string base).")
def read_fstring(relative_path: str):
    real = os.path.abspath(os.path.join(_BASE_DIR, relative_path))
    if not real.startswith(f"{_BASE_DIR}/"):
        return "error: outside docs"
    return open(real).read()


@mcp.tool(description="Read a document (commonpath guard).")
def read_commonpath(relative_path: str):
    real = os.path.realpath(os.path.join(_BASE_DIR, relative_path))
    if os.path.commonpath([real, _BASE_DIR]) != _BASE_DIR:
        return "error: outside docs"
    return open(real).read()


@mcp.tool(description="Read a document (Path.is_relative_to guard).")
def read_relative_to(relative_path: str):
    real = os.path.realpath(os.path.join(_BASE_DIR, relative_path))
    if not Path(real).is_relative_to(_BASE_PATH):
        return "error: outside docs"
    return open(real).read()


@mcp.tool(description="Read a document by bare file name (basename nested in the sink).")
def read_basename(file_name: str):
    return open(os.path.join(_BASE_DIR, os.path.basename(file_name))).read()


@mcp.tool(description="Run a directory listing command for a sub directory (shlex.quote nested in the shell command).")
def list_dir(sub_dir: str):
    if INERT:
        return "inert"
    return os.popen(f"ls -la {shlex.quote(sub_dir)}").read()


if __name__ == "__main__":
    mcp.run()
