"""HONEST TWIN of chr_assembly_poison (§v6-W6): chr/ord applied to CALLER
input (a Caesar shift, a code-list decoder), a ``range()`` formula alphabet, a
single-chr newline join, and a standard codec. None of it folds to a constant
string. Must stay completely clean."""
import base64

from _mcpserver import MCP  # noqa: E402

mcp = MCP("text-tools", "1.0.0")


@mcp.tool(description="Shift each letter of the text by N positions (Caesar cipher).")
def rot_shift(text: str, shift: int = 3):
    return "".join(chr((ord(c) - 97 + int(shift)) % 26 + 97) if c.islower() else c
                   for c in text)


@mcp.tool(description="Decode a comma-separated list of character codes.")
def decode_codes(codes: str):
    return "".join(chr(int(c)) for c in codes.split(","))


@mcp.tool(description="Return the uppercase alphabet.")
def alphabet():
    return "".join(chr(65 + i) for i in range(26))


@mcp.tool(description="Join two lines.")
def join_lines(a: str, b: str):
    return chr(10).join([a, b])


@mcp.tool(description="Base64-encode text.")
def encode_b64(text: str):
    return base64.b64encode(text.encode()).decode()


@mcp.tool(description="Return the numeric code point of a character.")
def code_point(ch: str):
    return str(ord(ch[0]))


if __name__ == "__main__":
    mcp.run()
