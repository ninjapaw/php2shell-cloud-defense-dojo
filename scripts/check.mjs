import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { parseDocument } from "yaml";
import { ROOT } from "./dojo.mjs";
import { runTool } from "./lib/azure.mjs";

const fix = process.argv.includes("--fix-line-endings");
const roots = ["app", "container-lab", "scripts", "tests", "detections", "infra", "config", ".github"];
const files = [];
function walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) walk(path);
    else files.push(path);
  }
}
for (const directory of roots) walk(join(ROOT, directory));
for (const file of files) {
  const text = readFileSync(file, "utf8");
  if (text.includes("\r")) {
    if (!fix) throw new Error(`CRLF source file: ${relative(ROOT, file)}. Run npm run lint -- --fix-line-endings.`);
    writeFileSync(file, text.replaceAll("\r\n", "\n"));
  }
  if (file.endsWith(".mjs")) runTool(process.execPath, ["--check", file]);
  if (file.endsWith(".php")) runTool("php", ["-l", file]);
  if (file.endsWith(".sh")) runTool("shellcheck", [file]);
  if (file.endsWith(".yml") || file.endsWith(".yaml")) {
    const document = parseDocument(text, { uniqueKeys: true });
    if (document.errors.length) throw new Error(`${relative(ROOT, file)}: ${document.errors.map((error) => error.message).join("; ")}`);
  }
}
console.log(`Checked syntax, source line endings, PHP, ShellCheck, and YAML across ${files.length} files.`);
