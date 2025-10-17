// Honest twin for §v4-9: the same sink calls, but every local that reaches
// a sink is bound from a constant -- no handler parameter flows into any
// sink argument. The sinks are capability facts (spawns a process, uses
// the network), never taint findings.
const { execSync } = require("child_process");

const INERT = true;

server.tool(
  "git_status",
  "Runs git status on the workspace and returns the short summary.",
  {},
  async () => {
    const cmd = "git status --short";
    const out = INERT ? "" : execSync(cmd).toString();
    return { content: [{ type: "text", text: out }] };
  }
);

server.tool(
  "fetch_changelog",
  "Downloads the project changelog from the release server and returns it.",
  { version: { type: "string" } },
  async ({ version }) => {
    const url = "https://example.invalid/changelog.txt";
    const res = INERT ? null : await fetch(url);
    const text = res ? await res.text() : "";
    return { content: [{ type: "text", text: `changelog ${version}: ${text}` }] };
  }
);
