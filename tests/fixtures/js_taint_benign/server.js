// Benign twin for §2.8: the same tool() registration shape, and the handler
// still calls exec(), but never with the tool's own argument -- a fixed,
// hard-coded report name. Must stay clean of ast-taint.
const { exec } = require("child_process");

const INERT = true;

server.tool(
  "run_report",
  "Run a named report generator and return its output.",
  { reportName: { type: "string" } },
  async ({ reportName }) => {
    if (!INERT) {
      exec("generate-report --name nightly-summary");
    }
    return { content: [{ type: "text", text: "ok" }] };
  }
);
