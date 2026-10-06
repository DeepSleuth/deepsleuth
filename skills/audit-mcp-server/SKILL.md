---
name: audit-mcp-server
description: Audit an MCP server for tool-poisoning, schema abuse, and supply-chain risk with the deepsleuth scanner before wiring it into an agent. Use when the user wants to vet, screen, or scan an MCP server, a server directory, an mcp.json, or a launch command.
---

# Audit an MCP server with deepsleuth

Deepsleuth is a deterministic scanner — no LLM in the loop, every finding is
a rule match with cited evidence. Use it whenever a server the user is about
to trust needs a first-pass security review.

## When to use

- The user asks to vet / screen / audit / "make sure it's safe" an MCP server.
- The user hands you a server directory, an `mcp.json`, or a raw stdio launch
  command and wants it checked first.

## How to run

From the plugin root (or any installed checkout):

```bash
# 1) static pass — fast, no Docker needed
python3 -m deepsleuth scan <target> --no-dynamic

# 2) full pass — adds the sandboxed dynamic layer (requires the Docker CLI)
python3 -m deepsleuth scan <target>
```

`<target>` is a server **directory**, an **`mcp.json`** file, or a **raw
launch command** string, e.g. `"python3 server.py"` or `"npx -y some-pkg"`.

Alternatively call the `scan_target` tool of the `deepsleuth` MCP server
(this plugin's own server) with the target string.

## Reading the output

- Findings carry `severity`/`confidence` (`high`+ = actionable) and the exact
  matched text in `evidence`. Read the evidence, not just the label.
- **Skipped/notes matter**: `no local source analyzed for this command target`
  means the static layer had nothing to chew on — get the server's directory
  (or its unpacked package) and scan that too. `dynamic layer disabled`
  means the sandboxed runtime pass did not run.
- A raw `npx <package>` command cannot be statically analyzed until the
  package is unpacked; scan the unpacked directory for real coverage.

## After the scan

- Report each finding with its severity and the quoted evidence.
- For a server the user still wants to use despite findings, suggest Frontend
  A: run it behind the inline proxy gate
  (`python3 -m deepsleuth proxy <target> --fail-closed`) so every tool call
  is screened at runtime.