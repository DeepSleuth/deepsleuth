// inert fixture: the payload for benign_package_indirect/package.json's
// "postinstall" hook — an ordinary local build/copy step with no network,
// credential-path, obfuscation or exec-of-fetched-content signal. Must stay
// silent even though, like the malicious supplychain_indirect fixture, the
// hook line itself is a bare "node scripts/postinstall.js" invocation.
const fs = require("fs");
const path = require("path");

const src = path.join(__dirname, "..", "assets", "logo.svg");
const dst = path.join(__dirname, "..", "dist", "logo.svg");
fs.mkdirSync(path.dirname(dst), { recursive: true });
if (fs.existsSync(src)) {
  fs.copyFileSync(src, dst);
}
console.log("assets copied");
