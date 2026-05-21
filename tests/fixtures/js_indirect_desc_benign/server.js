// §v5-8 HONEST twin: the same indirection shapes -- an identifier over two
// hops, a property of a constant object, a template literal with ${CONST}
// parts, an array .join, concatenation across constants, a zod .describe()
// given as an object property, a low-level descriptor -- holding ordinary
// documentation. Resolving the text must not make anything actionable.
const PRODUCT = "Acme Docs";
const BASE_SEARCH = "Search the documentation index and return the ten best matches.";
const SEARCH_DESC = BASE_SEARCH;

const TEXTS = Object.freeze({
  // the user's page fetcher
  fetch: "Fetch a documentation page by its path and return it as markdown.",
  "export": `Export the items of a collection as CSV for ${PRODUCT}.`,
});

const NOTE = "Returns the display name, the avatar and the join date.";
const INTRO = "Counts the items in a list.";
const DETAIL = "Archived items are not counted.";

const SCHEMA_TEXTS = {
  reportId: "The report id to fetch",
  format: "Output format, either pdf or csv. Defaults to pdf.",
};

const reportParams = z.object({
  reportId: z.string().describe(SCHEMA_TEXTS.reportId),
  format: z.string().optional().describe(SCHEMA_TEXTS.format),
});

server.tool("search_docs", SEARCH_DESC, { query: z.string() }, async ({ query }) => {
  return { content: [{ type: "text", text: "ok" }] };
});

server.registerTool(
  "fetch_page",
  { description: TEXTS.fetch, inputSchema: { path: z.string() } },
  async ({ path }) => {
    return { content: [{ type: "text", text: "ok" }] };
  }
);

server.tool(
  "get_profile",
  `Fetches a user's profile from ${PRODUCT}. ${NOTE}`,
  { userId: z.string() },
  async ({ userId }) => {
    return { content: [{ type: "text", text: "ok" }] };
  }
);

server.tool(
  "list_items",
  [
    "Lists the items of a collection.",
    "Results are sorted by creation date.",
  ].join(" "),
  { collection: z.string() },
  async ({ collection }) => {
    return { content: [{ type: "text", text: "ok" }] };
  }
);

server.tool("count_items", INTRO + " " + DETAIL, { collection: z.string() }, async ({ collection }) => {
  return { content: [{ type: "text", text: "0" }] };
});

server.tool("get_report", "Fetch a report by id.", reportParams, async ({ reportId, format }) => {
  return { content: [{ type: "text", text: "ok" }] };
});

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "export_items",
      description: TEXTS["export"],
      inputSchema: { type: "object", properties: { collection: { type: "string" } } },
    },
  ],
}));
