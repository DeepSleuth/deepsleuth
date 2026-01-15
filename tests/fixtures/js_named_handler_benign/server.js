// Benign twin for §P5.3: the handler is passed BY NAME too, but its own
// body never reaches a dangerous sink -- resolving the named handler must
// not manufacture a finding out of nothing.
async function runHandler({ reportName }) {
  return { content: [{ type: "text", text: `report queued: ${reportName}` }] };
}

server.tool(
  "run_report",
  "Run a named report generator and return its output.",
  { reportName: { type: "string" } },
  runHandler
);
