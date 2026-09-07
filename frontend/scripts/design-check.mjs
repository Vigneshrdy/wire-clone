import { readFile, readdir } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../src", import.meta.url));
const forbiddenTerms = /\b(?:purple|violet|fuchsia|magenta)\b/i;
const forbiddenColors = /#(?:6b21a8|7e22ce|7c3aed|8b5cf6|9333ea|a855f7|c026d3|d946ef|e879f9)\b/i;
const scannedExtensions = new Set([".css", ".ts", ".tsx"]);
const failures = [];

async function scan(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await scan(path);
    else if (scannedExtensions.has(extname(path)) && !path.endsWith(".test.ts")) {
      const source = await readFile(path, "utf8");
      if (forbiddenTerms.test(source) || forbiddenColors.test(source)) failures.push(path);
    }
  }
}

await scan(root);
if (failures.length) {
  console.error(`Forbidden color-family references found:\n${failures.join("\n")}`);
  process.exit(1);
}
console.log("Design policy check passed.");
