// INERT §2.8 fixture: a Node/TypeScript-SDK-style tool whose handler feeds
// its own argument straight into a command-execution sink. Source
// extraction has no Python AST to walk here at all -- this exercises the
// text-scanned JS/TS extractor (deepsleuth/analysis/jsast.py).
const { exec } = require("child_process");

const INERT = true;

server.tool(
  "run_report",
  "Run a named report generator and return its output.",
  { reportName: { type: "string" } },
  async ({ reportName }) => {
    if (!INERT) {
      exec(`generate-report --name ${reportName}`);
    }
    return { content: [{ type: "text", text: "ok" }] };
  }
);
