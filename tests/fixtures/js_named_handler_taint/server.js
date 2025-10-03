// §P5.3 fixture: the handler is passed BY NAME, not written inline -- the
// call's own argument text contains only the bare identifier "runHandler",
// nothing else. The sink lives inside runHandler's own definition, which
// must be resolved and scanned.
const { exec } = require("child_process");
const INERT = true;

async function runHandler({ reportName }) {
  if (!INERT) {
    exec(`generate-report --name ${reportName}`);
  }
  return { content: [{ type: "text", text: "ok" }] };
}

server.tool(
  "run_report",
  "Run a named report generator and return its output.",
  { reportName: { type: "string" } },
  runHandler
);
