import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
const escape = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");

export function validateDeploymentManifest(value) {
  if (!value || value.schemaVersion !== 1 || value.kind !== "core-wizard-source"
      || !/^[a-f0-9]{64}$/.test(value.sha256 ?? "") || !Number.isInteger(value.bytes)
      || value.bytes < 1000 || value.bytes > 262144 || value.parts !== 2 || !Array.isArray(value.files)
      || value.files.length < 20 || value.files.length > 60 || new Set(value.files).size !== value.files.length
      || value.files.some((file) => typeof file !== "string" || file.includes("..") || !/^[a-zA-Z0-9_./-]+$/.test(file))) {
    throw new Error("Deployment download manifest is missing or invalid; no unverified installer is offered.");
  }
  return value;
}

export async function deploymentManifest() {
  return validateDeploymentManifest(JSON.parse(await readFile(new URL("./public-deployment/manifest.json", import.meta.url), "utf8")));
}

export async function deploymentDownload() {
  const manifest = await deploymentManifest();
  const parts = await Promise.all(["00", "01"].map((index) => readFile(new URL(`./public-deployment/source.zip.${index}.b64`, import.meta.url), "utf8")));
  return decodeDeployment(manifest, parts);
}

export function decodeDeployment(value, parts) {
  const manifest = validateDeploymentManifest(value);
  if (!Array.isArray(parts) || parts.length !== 2 || parts.some((part) => typeof part !== "string")) throw new Error("Both fixed deployment ZIP parts are required.");
  const encoded = parts.join("");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length > 350000) throw new Error("Deployment ZIP encoding rejected.");
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.toString("base64") !== encoded || bytes.length !== manifest.bytes || createHash("sha256").update(bytes).digest("hex") !== manifest.sha256) {
    throw new Error("Deployment ZIP checksum mismatch; download denied.");
  }
  return bytes;
}

export function renderDeploymentPage(value) {
  const manifest = validateDeploymentManifest(value);
  return `<p class="evidence-label">DEPLOY TO YOUR OWN AZURE SUBSCRIPTION / CORE DEV TRAINING LAB</p>
<p>The simplest path is a local Node.js wizard using <code>az login</code>. No custom app registration, client secret, bundled Azure CLI, desktop installer or local web server is required. This website never receives your Azure credentials and never deploys using the hosted demo identity.</p>
<p><a href="/evidence/deploy/source.zip">Download the deployment wizard ZIP</a> / <a href="/evidence/deploy/source.sha256">SHA-256 checksum</a> / <a href="https://shell.azure.com/bash" rel="noreferrer">Open Azure Cloud Shell</a> / <a href="https://github.com/ninjapaw/php2shell-cloud-defense-dojo">Full GitHub project</a></p>
<h2>1. Install/check the few prerequisites</h2>
<ul><li><a href="https://nodejs.org/download/release/">Node24.19 or later on the24.x branch</a> (not25+ for this reviewed version).</li><li><a href="https://learn.microsoft.com/cli/azure/install-azure-cli">Microsoft Azure CLI2.61+</a>. Windows: official MSI/ZIP installation; macOS/Linux: the supported installer. Reopen the terminal afterward.</li><li>Bicep: the wizard checks <code>az bicep version</code> and asks before <code>az bicep install</code>. It never registers Azure providers or grants RBAC automatically.</li><li>Archive tool: built-in <code>tar.exe</code> on current Windows; <code>zip</code> on Linux/macOS. No local PHP or Docker is needed.</li></ul>
<p>Cloud Shell is an alternative if local installation is restricted. Open Bash, check the Node version and CLI components there, then run the same extracted wizard. Node24 is still required; Cloud Shell availability does not imply it is already the right version.</p>
<h2>2. Download, verify and extract before running</h2>
<p>Source package SHA-256:</p><pre><code>${manifest.sha256}</code></pre>
<p>Do not pipe downloaded text into a shell. Review the source and verify the checksum first. The ZIP contains only ${manifest.files.length} reviewed core deployment files, launchers and documentation, no credentials, live subscription binding, SDK dependency tree, private captures or container lab.</p>
<h3>PowerShell / Windows</h3>
<pre><code>Invoke-WebRequest https://php2proof.ninjapaws.org/evidence/deploy/source.zip -OutFile php2proof-deploy.zip
(Get-FileHash .\\php2proof-deploy.zip -Algorithm SHA256).Hash.ToLowerInvariant()
# Compare with the exact checksum above, then:
Expand-Archive -LiteralPath .\\php2proof-deploy.zip -DestinationPath .\\php2proof-deploy
Set-Location .\\php2proof-deploy
node .\\scripts\\wizard.mjs --check
node .\\scripts\\wizard.mjs</code></pre>
<p>Optional launcher: <code>.\\scripts\\start.ps1</code>. If enterprise execution policy blocks unsigned PowerShell scripts, use the direct Node command or an approved Cloud Shell/WSL environment; do not bypass your policy. Native Windows invokes the official Azure CLI's bundled Python module directly, never an interpolated cmd.exe command.</p>
<h3>Bash / macOS / Linux / Cloud Shell</h3>
<pre><code>curl --fail --location --output php2proof-deploy.zip https://php2proof.ninjapaws.org/evidence/deploy/source.zip
shasum -a 256 php2proof-deploy.zip
# Compare with the exact checksum above, then extract to a new directory:
unzip php2proof-deploy.zip -d php2proof-deploy
cd php2proof-deploy
bash scripts/start.sh --check
bash scripts/start.sh</code></pre>
<p>Linux may use <code>sha256sum</code> instead of <code>shasum</code>. The repository version is also available as <code>node scripts/wizard.mjs</code>; no npm installation is needed just to run the core wizard.</p>
<h2>3. Answer the essential questions</h2>
<ol><li>Use an already signed-in Azure CLI identity or approve browser/WAM/device-code sign-in. Passwords, MFA and tenant consent stay with Microsoft, not this app. <a href="https://learn.microsoft.com/cli/azure/authenticate-azure-cli-interactively">Azure CLI authentication</a> uses Microsoft's existing client; RBAC and tenant policy still apply.</li><li>Choose an enabled subscription, region, unique suffix, new owned group,1–72-hour metadata lifetime and PHP8.4/8.5 branch.</li><li>Explicitly choose paid Defender CSPM/Sentinel/analytics opt-ins, all defaulting off. Existing plans are never disabled. The demo's domain is never adopted.</li><li>Save the nonsecret <code>.azure/profiles/&lt;suffix&gt;.json</code> file and select an action.</li></ol>
<p>Normal Azure charges include Front Door Premium/WAF, Linux B1, logs/traffic and any opt-in service. No price or free-tier guarantee is invented. The1-GB/day log ingestion cap is not a budget. <strong>Expiry is metadata, not automatic deletion or stopped billing.</strong></p>
<h2>4. Install, test, repair and remove safely</h2>
<p>The menu offers offline plan, doctor/what-if, new install, validate, five harmless GhostPaw requests, investigate, WAF Prevention, fixture removal, repair and uninstall. No simulation follows install automatically. Every write requires typing the exact group name; install refuses an existing group. What-if runs before deploy/repair/protection and the actual lifecycle rechecks it.</p>
<pre><code>node scripts/wizard.mjs --profile .azure/profiles/&lt;your-suffix&gt;.json</code></pre>
<p>Use that same profile for all later actions. Repair preserves original expiry, fixed state and Prevention; it does not reopen exposure. Uninstall deletes only the exact tagged main group after confirmation, never a subscription/tenant, shared Defender plan, DNS zone or separate advanced environment. Remove this run's CNAME before releasing its hostname.</p>
<h2>5. What is and is not deployed</h2>
<p><strong>Included:</strong> the core public PHP story, guided walkthrough, real Front Door/WAF behavior, synthetic app fixtures, monitoring and explicitly selected optional components. Check actual runtime patch level and findings; a PHP branch or a fixed fixture is not a CVE fix. Historical evidence links go to the clearly labelled central reference recording, not invented logs for your new deployment.</p>
<p><strong>Advanced/separate:</strong> the authenticated Node administrator portal, private Key Vault/Storage/networking, raw private evidence collection, tenant-wide XDR onboarding and the private container comparison. These are not silently installed by the simple wizard. Read <code>docs/deployment.md</code> and the full project's <code>operator/README.md</code> before those additional IAM, cost, credential and networking steps.</p>
<p><a href="https://php2proof.ninjapaws.org/walkthrough.php">Reference walkthrough</a> / <a href="https://php2proof.ninjapaws.org/evidence/response">Official-response mitigation/resolution guide</a>. Download integrity and successful deployment still require your local checks and actual Azure readback.</p>
<details><summary>Reviewed files in this distribution</summary><pre>${escape(manifest.files.join("\n"))}</pre></details>`;
}

export async function deploymentPage() { return renderDeploymentPage(await deploymentManifest()); }
