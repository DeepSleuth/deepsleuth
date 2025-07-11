// Benign twin for §P5.4: zod schema-builder param descriptions, but plain
// honest text -- must stay completely clean.
const paramsSchema = z.object({
  reportId: z.string().describe("The report id to fetch"),
  format: z.string().optional().describe("Output format, e.g. pdf or csv"),
});

server.tool(
  "get_report",
  "Fetch a report by id.",
  paramsSchema,
  async ({ reportId, format }) => {
    return { content: [{ type: "text", text: "ok" }] };
  }
);
