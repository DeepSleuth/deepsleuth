"""§v5-6 HONEST twin: the same listing layout — annotations, a title, an
output schema, a nested vendor field, enum descriptions, examples, a nested
input-schema property — with ordinary documentation strings in every field
(including a title that states the tool's own function as an opening
imperative, an example carrying an encoded sample payload, and a note that
mentions a sibling tool without any force). Nothing here may be actionable.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("notes", "1.0.0")


@mcp.tool(description="Get the current weather for a city.",
          annotations={"readOnlyHint": True, "title": "Weather lookup for a single city"})
def get_weather(city: str):
    return f"sunny in {city}"


@mcp.tool(description="Get the three-day forecast for a city.")
def get_forecast(city: str):
    return f"mild in {city}"


@mcp.tool(description="List the saved notes.")
def list_notes():
    return "[]"


@mcp.tool(description="Search the saved notes.")
def search_notes(query: str, mode: str = "fast"):
    return "[]"


@mcp.tool(description="Add a note.")
def add_note(text: str):
    return "added"


@mcp.tool(description="Rename a note.")
def rename_note(note_id: str, options: str = ""):
    return "renamed"


@mcp.tool(description="Upload a note to remote storage.",
          annotations={"title": "Upload a note to the remote storage bucket",
                       "openWorldHint": True})
def upload_note(note_id: str):
    return "uploaded"


@mcp.tool(description="Export every note as one text bundle.")
def export_all_notes():
    return ""


def _extend(tool_name, **fields):
    for entry in mcp._tools:
        if entry["name"] == tool_name:
            entry.update(fields)


_extend("get_forecast", outputSchema={
    "type": "object",
    "properties": {"summary": {
        "type": "string",
        "description": "A one-line summary of the next three days."}}})
_extend("list_notes", **{"x-usage": {"notes": [
    "Results are cached for ten minutes.",
    "See also export_all_notes for a single text bundle."]}})
_extend("search_notes", inputSchema={
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "Text to look for."},
        "mode": {"type": "string", "enum": ["fast", "deep"],
                 "enumDescriptions": [
                     "Fast scan of the titles only.",
                     "Deep scan of every note, including archived ones."]}},
    "required": ["query"]})
_extend("add_note", examples=[
    "add_note(text='buy milk')",
    "An attachment is passed as base64 text, for example aGVsbG8gd29ybGQgZnJvbSBhIG5vdGU="])
_extend("rename_note", inputSchema={
    "type": "object",
    "properties": {
        "note_id": {"type": "string", "description": "The note to rename."},
        "options": {"type": "object", "properties": {"reason": {
            "type": "string",
            "description": "An optional reason recorded in the note history."}}}},
    "required": ["note_id"]})
_extend("upload_note", title="Upload a note to remote storage")


if __name__ == "__main__":
    mcp.run()
