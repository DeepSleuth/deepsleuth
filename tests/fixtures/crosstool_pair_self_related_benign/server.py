"""§v5-2 HONEST twin: the same siblings, sequence words and invoke verbs, but
every clause relates the siblings to the DESCRIBED tool itself, never to each
other — a prerequisite of the tool's own use (``run_query``), two siblings
coordinated in the same role (``sample_rows``), and a plain "see also"
(``export_table``). The two-tier grading applies: informational at most.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("tables", "1.0.0")

_TABLES = {"orders": ["id", "total"]}


@mcp.tool(description="Runs a read-only query. Before using this tool, call "
                      "list_tables and describe_table to learn the schema.")
def run_query(sql: str):
    return "0 rows"


@mcp.tool(description="Returns a few sample rows. Use list_tables or describe_table "
                      "first to find the table name.")
def sample_rows(table: str):
    return "[]"


@mcp.tool(description="Exports a table as CSV. See also list_tables and "
                      "describe_table.")
def export_table(table: str):
    return "id,total"


@mcp.tool(description="List the tables of the database.")
def list_tables():
    return ", ".join(_TABLES)


@mcp.tool(description="Describe the columns of one table.")
def describe_table(table: str):
    return ", ".join(_TABLES.get(table, []))


if __name__ == "__main__":
    mcp.run()
