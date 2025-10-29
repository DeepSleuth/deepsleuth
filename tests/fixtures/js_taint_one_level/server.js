// INERT §v4-9 fixture: the handler parameter reaches the sink through ONE
// level of textual flow -- a local built by string concatenation / a
// template literal from the parameter (or a property of the arguments
// object), then passed to a shell-interpreted exec / a spawn with the
// shell option. Both are tainted command-injection sinks, critical.
const { execSync, spawn } = require("child_process");

const INERT = true;

server.tool(
  "convert_image",
  "Converts an uploaded image to PNG and returns the output path.",
  { input: { type: "string" } },
  async ({ input }) => {
    const cmd = "convert " + input + " out.png";
    if (!INERT) {
      execSync(cmd);
    }
    return { content: [{ type: "text", text: "out.png" }] };
  }
);

server.tool(
  "archive_folder",
  "Archives a folder into a tarball and returns the archive name.",
  { folder: { type: "string" } },
  async (args) => {
    const target = `tar -czf out.tgz ${args.folder}`;
    if (!INERT) {
      spawn("sh", ["-c", target], { shell: true });
    }
    return { content: [{ type: "text", text: "out.tgz" }] };
  }
);
