const { statSync, readFileSync } = require("node:fs");
const { win32 } = require("node:path");

function regularFile(path, stat = statSync) {
  try { return stat(path).isFile(); }
  catch (error) {
    if (["ENOENT", "ENOTDIR"].includes(error.code)) return false;
    throw error;
  }
}

function azureCommand(args, environment, { stat = statSync, read = readFileSync } = {}) {
  const entries = String(environment.Path ?? environment.PATH ?? "").split(";").filter(Boolean);
  for (const entry of entries) {
    const directory = entry.replace(/^"(.*)"$/, "$1");
    for (const name of ["az.exe", "az.cmd", "az.bat"]) {
      const launcher = win32.join(directory, name);
      if (!regularFile(launcher, stat)) continue;
      if (name === "az.exe") return { command: launcher, args };
      const python = win32.resolve(win32.dirname(launcher), "..", "python.exe");
      const source = read(launcher, "utf8");
      const installer = /SET\s+AZ_INSTALLER=(MSI|ZIP)\b/i.exec(source)?.[1].toUpperCase();
      if (!installer || !/\bpython\.exe\b/i.test(source) || !/-IBm\s+azure\.cli\b/i.test(source) || !regularFile(python, stat)) {
        throw new Error("Native Windows requires Microsoft's MSI/ZIP Azure CLI layout. Use the official installer, Azure Cloud Shell or WSL2; no cmd.exe fallback is used.");
      }
      return { command: python, args: ["-IBm", "azure.cli", ...args], installer };
    }
  }
  throw new Error("Azure CLI was not found. Install Microsoft's Azure CLI, reopen the terminal, then rerun the prerequisite check.");
}

function windowsTool(command, args, options = {}, dependencies) {
  if (command === "az") {
    const plan = azureCommand(args, options.env ?? process.env, dependencies);
    return { command: plan.command, args: plan.args,
      options: { ...options, env: { ...(options.env ?? process.env), ...(plan.installer ? { AZ_INSTALLER: plan.installer } : {}) } } };
  }
  if (command === "zip") {
    if (JSON.stringify(args) === '["-v"]') return { command: "tar.exe", args: ["--version"], options };
    if (args.length === 4 && args[0] === "-q" && args[1] === "-r" && args[3] === "." && options.cwd) {
      return { command: "tar.exe", args: ["-a", "-c", "-f", args[2], "-C", options.cwd, "."], options };
    }
    throw new Error("Unsupported archive operation; only the fixed application ZIP packaging is allowed.");
  }
  return { command, args, options };
}

module.exports = { azureCommand, windowsTool };
