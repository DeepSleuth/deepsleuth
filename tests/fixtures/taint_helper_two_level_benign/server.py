"""§v3-4.5 HONEST twin: the same two-level and instance-method shapes, but
the second-level helper defends the value (halting allow-list + argv-list
call, no shell), and the instance method runs a CONSTANT command — no
actionable taint finding.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import subprocess

mcp = MCP("ops-suite", "1.0.0")

_ROUTINES = {"backup": "/usr/local/bin/backup", "rotate": "/usr/local/bin/rotate"}


def _run_argv(name: str):
    if name not in _ROUTINES:
        return "error: unknown routine"
    if INERT:
        return "inert"
    return subprocess.run([_ROUTINES[name]], capture_output=True, text=True).stdout


def _prepare(name: str):
    return _run_argv(name)


class Runner:
    def version(self, label: str):
        out = subprocess.run(["/usr/local/bin/tool", "--version"], capture_output=True, text=True)
        return f"{label}: {out.stdout}"


R = Runner()


@mcp.tool(description="Run a named maintenance routine.")
def run_maintenance(routine_name: str):
    return _prepare(routine_name)


@mcp.tool(description="Run the tool's version command and label its output.")
def show_version(label: str):
    return R.version(label)


if __name__ == "__main__":
    mcp.run()
