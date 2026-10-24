import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { redact, sameId } from "./safety.mjs";

export function runTool(command, args, options = {}) {
  if (process.platform === "win32" && command === "az") {
    throw new Error("Azure lifecycle commands require Linux/macOS or WSL2 with Linux Node and Azure CLI. Native Windows supports offline plan/tests.");
  }
  const result = spawnSync(command, args, {
    encoding: "utf8", timeout: 1_800_000, maxBuffer: 4 * 1024 * 1024, shell: false,
    ...options,
  });
  if (result.error) throw new Error(`Cannot run ${command}: ${redact(result.error.message)}`);
  if (result.status !== 0) throw new Error(`${command} failed (${result.status}): ${redact(result.stderr || "no diagnostic output")}`);
  return result.stdout;
}

export function createAzureClient(config, runner = runTool) {
  return (args) => {
    const subscriptionArgs = args[0] === "account" || args[0] === "cloud" ? [] : ["--subscription", config.subscription];
    const whatIfArgs = args[0] === "deployment" && args[2] === "what-if" && !args.includes("--no-pretty-print")
      ? ["--no-pretty-print"] : [];
    let text;
    try {
      text = runner("az", [...args, ...whatIfArgs, ...subscriptionArgs, "--only-show-errors", "--output", "json"], {
        env: { ...process.env, AZURE_EXTENSION_USE_DYNAMIC_INSTALL: "no", AZURE_CORE_COLLECT_TELEMETRY: "false" },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Azure ${args.slice(0, 3).join(" ")}: ${redact(message)}`);
    }
    if (!text.trim()) return null;
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error("Azure CLI returned invalid JSON; response omitted to avoid leaking diagnostics.");
    }
    if (args[0] === "webapp" && args[1] === "show" && value?.appServicePlanId != null) {
      if (typeof value.appServicePlanId !== "string" || !value.appServicePlanId.length
          || (value.serverFarmId != null && !sameId(value.serverFarmId, value.appServicePlanId))) {
        throw new Error("Azure CLI returned invalid or conflicting App Service plan identifiers.");
      }
      value.serverFarmId = value.appServicePlanId;
    }
    return value;
  };
}

export function readAzureCollection(az, initialUrl) {
  const expected = new URL(initialUrl);
  if (expected.origin !== "https://management.azure.com" || expected.username || expected.password || expected.hash) {
    throw new Error("Azure collection requests must use the public management endpoint without URL credentials or fragments.");
  }
  const values = [];
  let url = initialUrl;
  for (let page = 0; url && page < 10; page += 1) {
    const parsed = new URL(url);
    if (parsed.origin !== expected.origin || parsed.pathname.toLowerCase() !== expected.pathname.toLowerCase()
        || parsed.username || parsed.password || parsed.hash) {
      throw new Error("Unexpected Azure collection continuation URL.");
    }
    const response = az(["rest", "--method", "get", "--url", url]);
    if (!Array.isArray(response?.value)) throw new Error("Invalid Azure collection response: expected a value array.");
    if (response.nextLink != null && (typeof response.nextLink !== "string" || !response.nextLink.length)) {
      throw new Error("Invalid Azure collection continuation link.");
    }
    values.push(...response.value);
    url = response.nextLink;
  }
  if (url) throw new Error("Azure collection pagination exceeded the bounded 10-page limit.");
  return values;
}

export function checkTools() {
  runTool("az", ["bicep", "version"]);
  runTool("zip", ["-v"]);
}

export function packageApp(root) {
  const directory = mkdtempSync(join(tmpdir(), "php2shell-app-"));
  const path = join(directory, "app.zip");
  try {
    runTool("zip", ["-q", "-r", path, "."], { cwd: join(root, "app") });
  } catch (error) {
    rmSync(directory, { recursive: true });
    throw error;
  }
  return { path, cleanup: () => rmSync(directory, { recursive: true }) };
}
