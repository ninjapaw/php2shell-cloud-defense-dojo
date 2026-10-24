<?php
declare(strict_types=1);
require_once __DIR__ . '/lab.php';

allow_read_only();
$state = lab_state();
if ($_GET !== []) {
    json_response(['error' => 'The walkthrough accepts no training inputs or configuration changes.'], 400);
}
security_headers();
header('Content-Type: text/html; charset=utf-8');
$fixed = $state === 'fixed';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PHP to Proof | Guided Walkthrough</title>
  <meta name="description" content="A step-by-step PHP to Proof walkthrough: what to do, what evidence to expect, and what changes with and without Defender CSPM, workload protection, and Microsoft Sentinel.">
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <a class="skip-link" href="#main">Skip to main content</a>
  <header class="topbar"><a href="/" class="brand">NINJAPAW <span>/ DEFENSE DOJO</span></a><nav aria-label="Primary"><a href="/">Story</a><a href="/walkthrough.php" aria-current="page">Walkthrough</a></nav><span class="badge">PUBLIC DEMO</span></header>
  <main id="main" class="walkthrough">
    <aside class="warning"><strong>TRAINING ONLY.</strong> This is an evidence-led investigation, not an exploit demonstration. No shell, real outbound connection, secret read, or compromise is produced.</aside>
    <section class="hero">
      <p class="eyebrow">MISSION BRIEFING / A GUIDED CODE-TO-CLOUD STORY</p>
      <h1>PHP to Proof.<br><span>The guided walkthrough.</span></h1>
      <p class="intro">Follow a PHP request from exposure to verified closure, with and without Defender components.</p>
      <p class="walkthrough-state"><strong>Application state: <?= escape($state) ?>.</strong> <?= $fixed ? 'Training endpoints have been removed. Read the story, but do not expect the simulator to run against this fixed application.' : 'Synthetic endpoints are available to the bounded operator simulator. Reading this guide does not run them.' ?></p>
      <p class="walkthrough-notice"><strong>Defender and Sentinel status: not queried by this page.</strong> Capabilities below are not live badges; omitted flags do not mean off. No additional app permissions are needed.</p>
    </section>

    <nav class="walkthrough-toc" aria-label="Walkthrough chapters">
      <h2>Your investigation route</h2>
      <ol>
        <li><a href="#briefing">Brief the team</a></li>
        <li><a href="#baseline">Discover and validate the asset</a></li>
        <li><a href="#request">Generate one bounded run</a></li>
        <li><a href="#correlate">Build the evidence timeline</a></li>
        <li><a href="#posture">Inspect actual Defender posture</a></li>
        <li><a href="#sentinel">Compare manual hunting and analytics</a></li>
        <li><a href="#protect">Prove WAF Prevention</a></li>
        <li><a href="#remediate">Remove, verify, and clean up</a></li>
        <li><a href="#debrief">Debrief and troubleshoot</a></li>
      </ol>
      <p><a href="#components">Component comparison</a> / <a href="#containers">Optional container track</a> / <a href="#glossary">Plain-language glossary</a></p>
    </nav>

    <section id="briefing" class="walkthrough-chapter" aria-labelledby="briefing-title">
      <p class="number">00 / SET THE EVIDENCE CONTRACT</p>
      <h2 id="briefing-title">Brief the team before touching the controls</h2>
      <p>A disposable Linux PHP App Service serves three fabricated records with zero runtime role grants. Front Door/WAF is public; the origin requires its service tag and profile header.</p>
      <details>
        <summary>Operator prerequisites and stop conditions</summary>
        <ul>
          <li>Read README and <code>docs/walkthrough.md</code>; approve subscription, costs, and exact owned group/suffix.</li>
          <li>Use Node 24.19+ within Node 24, PHP 8.4/8.5, and the documented Linux/WSL2 cloud tools. Native Windows supports offline planning/tests.</li>
          <li>Set <code>AZURE_SUBSCRIPTION_ID</code>/<code>DOJO_SUFFIX</code>. The group is in <code>config/dev.json</code>.</li>
          <li>Stop on ownership/HTTPS/origin failures. Never loosen controls, add app roles, or disable shared plans.</li>
        </ul>
      </details>
      <p class="footnote">Commands run from your repository-root operator terminal, never this page. Expiry is not automatic deletion; the log cap is not a budget.</p>
    </section>

    <section id="components" class="walkthrough-chapter" aria-labelledby="components-title">
      <p class="number">CHOOSE YOUR LENS / NOT A LIVE STATUS DASHBOARD</p>
      <h2 id="components-title">With and without the components</h2>
      <div class="table-wrap" role="region" aria-label="Security component comparison" tabindex="0">
        <table>
          <caption>Capabilities, not the subscription's observed plan status.</caption>
          <thead><tr><th scope="col">Component</th><th scope="col">Without it</th><th scope="col">With it / this repository's boundary</th></tr></thead>
          <tbody>
            <tr><th scope="row">WAF + Log Analytics</th><td>Removal unsupported.</td><td>Required: real edge records and synthetic app logs, subject to delivery.</td></tr>
            <tr><th scope="row">Paid Defender CSPM</th><td>Foundational CSPM still offers free recommendations/inventory.</td><td><code>--enable-defender-cspm</code>: subscription-wide <code>CloudPosture</code> Standard; supported graph/attack paths, not guaranteed findings.</td></tr>
            <tr><th scope="row">Serverless protection</th><td>Web App scanning unverified.</td><td>Separate CSPM component; verify settings, support, and assessments. Standard pricing alone is insufficient.</td></tr>
            <tr><th scope="row">Defender for App Service</th><td>No plan-specific alerts expected.</td><td>Separate plan, not the CSPM flag. Verify platform support; fixtures are not promised triggers.</td></tr>
            <tr><th scope="row">Defender for Servers / MDE</th><td>No endpoint telemetry here.</td><td>Requires an onboarded supported machine; this App Service is not an MDE device.</td></tr>
            <tr><th scope="row">Defender for Containers</th><td>Public lesson unchanged.</td><td>Separate private AKS track: existing plans, sensors, registry coverage, actual findings.</td></tr>
            <tr><th scope="row">Microsoft Sentinel</th><td>Manual Log Analytics KQL.</td><td><code>--enable-sentinel</code>: disabled Informational synthetic rule, no Defender connector.</td></tr>
            <tr><th scope="row">Synthetic analytics</th><td>Rule disabled.</td><td>Add <code>--enable-analytics</code> with Sentinel; <strong>incident creation is disabled</strong>.</td></tr>
          </tbody>
        </table>
      </div>
      <p>Check <strong>Defender for Cloud &gt; Environment settings</strong>. Operator <code>validate</code> reports observed <code>defenderCspm</code>, not every plan/scanner's coverage.</p>
    </section>

    <section id="baseline" class="walkthrough-chapter" aria-labelledby="baseline-title">
      <p class="number">01 / DISCOVER</p>
      <h2 id="baseline-title">First prove which asset you are looking at</h2>
      <p>Record resource ID, PHP version, environment, and state from <a href="/health.php">health JSON</a>. CVE search terms are not runtime findings.</p>
      <div class="walkthrough-compare">
        <article class="walkthrough-without"><h3>Without paid Defender CSPM</h3><p>Inspect configuration, health, WAF, and foundational recommendations.</p></article>
        <article class="walkthrough-with"><h3>With paid Defender CSPM</h3><p>Add supported Explorer relationships and actual assessments.</p></article>
      </div>
      <details>
        <summary>Operator steps and expected result</summary>
        <pre><code>bash scripts/dojo.sh plan --environment dev
bash scripts/dojo.sh doctor --environment dev
bash scripts/dojo.sh validate --environment dev</code></pre>
        <p>Plan/doctor do not deploy. Validate identities, HTTPS, B1, diagnostics, disabled basic publishing, zero app-scope grants, and direct-origin 403 with/without copied FDID.</p>
      </details>
    </section>

    <section id="request" class="walkthrough-chapter" aria-labelledby="request-title">
      <p class="number">02 / OBSERVE A BOUNDED RUN</p>
      <h2 id="request-title">A harmless request leaves a real edge trail</h2>
      <p>Five requests share one UUIDv4 after live target validation. Only the first has <code>dojoProbe=waf-marker</code>. No arbitrary target or exploit.</p>
      <pre><code>bash scripts/dojo.sh simulate --environment dev --yes</code></pre>
      <div class="walkthrough-compare">
        <article class="walkthrough-without"><h3>Without workload protection</h3><p>Real WAF evaluation; labelled PHP JSON/<code>DOJO_EVENT</code>. Save run, UTC window, host/resource.</p></article>
        <article class="walkthrough-with"><h3>With workload protection</h3><p>Same safe run. Any real alert needs independent observation; none is promised.</p></article>
      </div>
      <p class="walkthrough-check"><strong>Detection:</strong> five HTTP 200s. The custom Block rule logs without enforcement; verify its delivered record. Not a CVE test.</p>
    </section>

    <section id="correlate" class="walkthrough-chapter" aria-labelledby="correlate-title">
      <p class="number">03 / SEPARATE OBSERVATION FROM SIMULATION</p>
      <h2 id="correlate-title">Build the timeline, then label every piece of evidence</h2>
      <p>In the lab workspace's Logs, set <code>RunIdFilter</code> and the UTC window. Delivered WAF records use <code>AzureDiagnostics</code>; PHP console events use <code>AppServiceConsoleLogs</code>.</p>
      <div class="table-wrap" role="region" aria-label="Signal evidence boundaries" tabindex="0">
        <table>
          <caption>Real ingestion does not make simulated behavior real.</caption>
          <thead><tr><th scope="col">Signal</th><th scope="col">Expected evidence</th><th scope="col">Not demonstrated</th></tr></thead>
          <tbody>
            <tr><th scope="row"><code>request</code></th><td>Real benign edge request; synthetic app event if it reaches PHP.</td><td>Exploitation/CVE protection.</td></tr>
            <tr><th scope="row"><code>php-error</code></th><td>Simulated error string.</td><td>Actual exception or crash.</td></tr>
            <tr><th scope="row"><code>process-synthetic</code></th><td>Process-shaped fixture.</td><td>Child process, shell, MDE event.</td></tr>
            <tr><th scope="row"><code>outbound-synthetic</code></th><td>Connection-shaped fixture.</td><td>Real egress or network detection.</td></tr>
            <tr><th scope="row"><code>canary</code></th><td>Three fabricated in-code records.</td><td>Secret/data-plane read or exfiltration.</td></tr>
          </tbody>
        </table>
      </div>
      <p>Run <code>detections/waf-requests.kql</code> and <code>correlation.kql</code>; replace <code>__APP_RESOURCE_ID__</code>. The complete operator guide maps all six queries. Check rule/action, request/reference, resource/time, and <code>synthetic: true</code> before joining.</p>
      <p>No <code>DeviceProcessEvents</code>/<code>DeviceNetworkEvents</code> are supplied here. Independently corroborate any supported telemetry elsewhere; never relabel fixtures or invent missing records.</p>
    </section>

    <section id="posture" class="walkthrough-chapter" aria-labelledby="posture-title">
      <p class="number">04 / REVIEW THE ACTUAL RISK CONTEXT</p>
      <h2 id="posture-title">Ask Defender what it observed, not what the slide needs</h2>
      <pre><code>bash scripts/dojo.sh investigate --environment dev</code></pre>
      <p>Reads scoped PHP/CVE assessments; prints, but does not execute, the estate hunting catalog.</p>
      <div class="walkthrough-compare">
        <article class="walkthrough-without"><h3>Without paid CSPM features</h3><p>Review configuration, recommendations, advisory/version. Empty is not clearance.</p></article>
        <article class="walkthrough-with"><h3>With paid CSPM features</h3><p>Inspect returned graph/paths and relevant components; pricing is not scanning.</p></article>
      </div>
      <details>
        <summary>Optional billable CSPM step and honest expectations</summary>
        <pre><code>bash scripts/dojo.sh plan --environment dev --enable-defender-cspm
bash scripts/dojo.sh deploy --environment dev --yes --enable-defender-cspm</code></pre>
        <p>Subscription-wide Standard, not other workload plans. CVE-2026-109618/CVE-2026-109619 are search terms, not findings. <code>SecurityRecommendation</code> export is not configured.</p>
      </details>
    </section>

    <section id="sentinel" class="walkthrough-chapter" aria-labelledby="sentinel-title">
      <p class="number">05 / FROM MANUAL HUNT TO OPTIONAL ANALYTICS</p>
      <h2 id="sentinel-title">Correlation is not automatically an incident</h2>
      <div class="walkthrough-compare">
        <article class="walkthrough-without"><h3>Without Sentinel</h3><p>Hunt with the same KQL in Log Analytics; no incident or scheduled evaluation is expected.</p></article>
        <article class="walkthrough-with"><h3>With Sentinel and analytics</h3><p>Matching data can produce an Informational synthetic alert, not a Defender detection. <code>createIncident: false</code>.</p></article>
      </div>
      <details>
        <summary>Choose workspace onboarding or enabled analytics explicitly</summary>
        <pre><code># Sentinel only: installs the rule disabled
bash scripts/dojo.sh plan --environment dev --enable-sentinel
bash scripts/dojo.sh deploy --environment dev --yes --enable-sentinel

# Optional analytics after cost/query review
bash scripts/dojo.sh plan --environment dev --enable-sentinel --enable-analytics
bash scripts/dojo.sh deploy --environment dev --yes --enable-sentinel --enable-analytics</code></pre>
        <p>Every 15 minutes over one hour: WAF marker and at least two distinct synthetic app signals for the same run plus recent ingestion. Late data can miss; matches can repeat. No timing guarantee.</p>
        <p>No Defender connector, export, playbook, incident creation, or estate hunt is enabled.</p>
      </details>
    </section>

    <section id="protect" class="walkthrough-chapter" aria-labelledby="protect-title">
      <p class="number">06 / ENFORCE AND RE-TEST</p>
      <h2 id="protect-title">Make one deliberate prevention change</h2>
      <p>Review normal traffic, the actual benign-rule match, and origin isolation before changing mode.</p>
      <pre><code>bash scripts/dojo.sh protect --environment dev --yes
bash scripts/dojo.sh simulate --environment dev --yes</code></pre>
      <p class="walkthrough-check"><strong>Prevention:</strong> marker 403; four other simulator requests 200. The blocked marker never reaches PHP. Homepage/health must work; direct origin must still return 403.</p>
      <p>Works with or without paid Defender. WAF causes this block; it does not prove managed-rule CVE coverage.</p>
    </section>

    <section id="remediate" class="walkthrough-chapter" aria-labelledby="remediate-title">
      <p class="number">07 / REDUCE, VERIFY, AND CLEAN UP</p>
      <h2 id="remediate-title">Remove the training surface, not just the alert</h2>
      <pre><code>bash scripts/dojo.sh remediate --environment dev --yes
bash scripts/dojo.sh validate --environment dev</code></pre>
      <p>Expect fixed state, Prevention, and working homepage/health. All five signals must return 404 <strong>without the WAF marker</strong>; a marked request can still get edge 403, which alone does not prove removal.</p>
      <p><code>simulate</code> refuses fixed state. <code>repair</code> preserves it, Prevention, and original expiry; it is not a reset or a verified CVE fix.</p>
      <p>Save isolation, diagnostics, publishing, and least-privilege evidence. If actual Defender findings exist, also verify the component fix and assessment refresh. Alert closure is not patching.</p>
      <details>
        <summary>Optional complete teardown: exact ownership and costs matter</summary>
        <pre><code>bash scripts/dojo.sh uninstall --environment dev \
  --confirm-resource-group '&lt;exact-owned-resource-group&gt;'</code></pre>
        <p>Confirm owned group from plan/configuration/tags. Only it is deleted; DNS and subscription plans remain. Remove this run's CNAME before releasing the hostname. Review costs with the owner; private AKS needs separate teardown.</p>
      </details>
    </section>

    <section id="containers" class="walkthrough-chapter" aria-labelledby="containers-title">
      <p class="number">OPTIONAL ADVANCED TRACK / A DIFFERENT LAB</p>
      <h2 id="containers-title">Want real affected-versus-fixed image evidence?</h2>
      <p><code>docs/container-lab.md</code>: private AKS, pinned PHP 8.4.26/8.4.27, existing Containers/CSPM/registry prerequisites. Verify versions, digests, sensors, and actual findings; OS findings are not necessarily PHP findings.</p>
      <p><code>test-detection</code> runs only administrative <code>id</code>, not an exploit or guaranteed alert. No public ingress.</p>
      <p class="footnote">Separate group, suffix, costs, evidence, and teardown. Never expose this private workload as the public DNS target.</p>
    </section>

    <section id="debrief" class="walkthrough-chapter" aria-labelledby="debrief-title">
      <p class="number">08 / DEBRIEF</p>
      <h2 id="debrief-title">What should you leave with?</h2>
      <ul class="walkthrough-checklist">
        <li>Exact asset/workspace identities, runtime, run IDs, and UTC windows.</li>
        <li>Real WAF action plus labelled synthetic evidence, or documented missing ingestion.</li>
        <li>Observed component settings and actual assessment/alert IDs, if present.</li>
        <li>Marker 200/403, working normal traffic, origin isolation, fixed unmarked 404.</li>
        <li>Least privilege, honest closure, and an explicit cleanup/cost decision.</li>
      </ul>
      <details>
        <summary>No result? Check the layer before changing the story</summary>
        <p>Check asset/version, component support, permissions, diagnostics, run/window, limits, and actual delivery. Configuration is not ingestion; no completion time is promised. No MDE rows or Sentinel incidents are expected here.</p>
        <p>Use the base endpoint while custom HTTPS awaits CNAME, Azure TXT/approval, WAF/route binding, and TLS. Stop on unexpected HTTPS/origin results. Full troubleshooting: <code>docs/walkthrough.md</code>.</p>
      </details>
    </section>

    <section id="glossary" class="walkthrough-chapter" aria-labelledby="glossary-title">
      <h2 id="glossary-title">Plain-language glossary</h2>
      <dl class="walkthrough-glossary">
        <dt>Posture / CSPM</dt><dd>Risk/configuration, not blocking.</dd>
        <dt>Workload protection</dt><dd>Supported detection with real telemetry.</dd>
        <dt>Log / alert / incident</dt><dd>Record / detector conclusion / grouped investigation.</dd>
        <dt>Assessment / attack path</dt><dd>Actual evaluation / product-returned chain, not a CVE keyword.</dd>
        <dt>Run ID / UTC window</dt><dd>Experiment UUID/time, excluding unrelated validation and probes.</dd>
        <dt>Synthetic</dt><dd>Fabricated content, even when genuinely ingested.</dd>
      </dl>
      <h3>Primary product references</h3>
      <p><a href="https://learn.microsoft.com/azure/defender-for-cloud/concept-cloud-security-posture-management">CSPM</a> / <a href="https://learn.microsoft.com/azure/defender-for-cloud/serverless-protection">Serverless protection</a> / <a href="https://learn.microsoft.com/azure/defender-for-cloud/defender-for-app-service-introduction">App Service</a>. Full references and costs: <code>docs/walkthrough.md</code>.</p>
      <p><a href="/">Return to the story</a> / <a href="#briefing">Start the walkthrough again</a></p>
    </section>
  </main>
  <footer>INDEPENDENT COMMUNITY PROJECT / NOT A MICROSOFT PRODUCT OR ENDORSEMENT <span>OBSERVE. LABEL. CORROBORATE. VERIFY.</span></footer>
</body>
</html>
