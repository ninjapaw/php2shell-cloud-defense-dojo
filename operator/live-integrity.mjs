import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

export const LIVE_INTEGRITY_FILES = Object.freeze([
  "operator/config.mjs", "operator/auth.mjs", "operator/azure.mjs", "operator/control.mjs", "operator/server.mjs",
  "operator/store.mjs", "operator/style.css", "operator/live-config.mjs", "operator/live-authorize.mjs",
  "operator/live-control.mjs", "operator/live-waf.mjs", "operator/live-azure.mjs", "operator/live.mjs",
  "operator/live-evidence.mjs", "operator/live-public.mjs", "operator/live-capture.mjs", "operator/live-integrity.mjs",
  "scripts/lib/private-live.mjs", "scripts/lib/container-lab.mjs", "scripts/lib/response.mjs", "container-lab/images.json",
]);

export async function assertLiveRuntimeIntegrity() {
  const manifest = JSON.parse(await readFile(new URL("./live-integrity.json", import.meta.url), "utf8"));
  if (manifest?.schemaVersion !== 1 || !manifest.files || Object.keys(manifest.files).length !== LIVE_INTEGRITY_FILES.length
      || Object.keys(manifest.files).some((name) => !LIVE_INTEGRITY_FILES.includes(name))) throw new Error("Private live source-integrity manifest is incomplete.");
  for (const name of LIVE_INTEGRITY_FILES) {
    const hash = manifest.files[name];
    if (!/^[a-f0-9]{64}$/.test(hash ?? "")) throw new Error("Invalid private live source-integrity fingerprint.");
    const bytes = await readFile(new URL(`../${name}`, import.meta.url));
    if (createHash("sha256").update(bytes).digest("hex") !== hash) throw new Error(`Private live source-integrity mismatch: ${name}. Execution remains disabled.`);
  }
}
