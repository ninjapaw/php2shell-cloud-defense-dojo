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
$moves = [
    [
        'signal' => 'request',
        'title' => 'A stranger at the edge',
        'intent' => 'Ghostpaw probes the public PHP entry point.',
        'without' => 'Triage request/WAF logs manually; these are not workload alerts.',
        'category' => 'Injection attempts',
        'with' => 'Supported injection detectors need real patterns, not this marker.',
        'control' => 'Keep the origin Front Door-only; verify the WAF rule/action.',
    ],
    [
        'signal' => 'php-error',
        'title' => 'An error becomes a clue',
        'intent' => 'Ghostpaw tries to turn PHP input into execution.',
        'without' => 'An error fixture is not a crash or affected-runtime finding.',
        'category' => 'Remote code execution',
        'with' => 'A fixture proves no CVE coverage; inspect actual request detections.',
        'control' => 'Check the actual PHP version/advisory; patch affected components.',
    ],
    [
        'signal' => 'process-synthetic',
        'title' => 'The attempted jump to a shell',
        'intent' => 'Ghostpaw attempts a child process outside the request handler.',
        'without' => 'Process fixture only; no process started or endpoint telemetry.',
        'category' => 'Web shell activity',
        'with' => 'Inspect real supported detections; this fixture creates no process or MDE event.',
        'control' => 'Remove execution paths; keep zero runtime role grants.',
    ],
    [
        'signal' => 'outbound-synthetic',
        'title' => 'A call that never leaves',
        'intent' => 'Ghostpaw tries to contact an external destination.',
        'without' => 'Connection fixture only; no connection or real destination.',
        'category' => 'Compromise indicators',
        'with' => 'No egress; no network detection is demonstrated.',
        'control' => 'Corroborate network evidence; a fixture is not command and control.',
    ],
    [
        'signal' => 'canary',
        'title' => 'The ledger stays fictional',
        'intent' => 'Ghostpaw searches for records and credentials.',
        'without' => 'Three fabricated records; no secret/data-plane read or exfiltration.',
        'category' => 'No guaranteed data-access alert',
        'with' => 'No sensitive data or canary detector; inspect actual findings.',
        'control' => 'Keep records fabricated; verify removal of training endpoints.',
    ],
];
$recordedRun = [
    'id' => '92ad189c-9a88-4403-b773-52453963e4b8',
    'startedAt' => '2026-10-24T16:33:41.463Z',
    'endedAt' => '2026-10-24T16:33:43.454Z',
    'capturedAt' => '2026-10-24T16:36:07.232Z',
    'applicationUtc' => [
        'request' => '2026-10-24T16:33:41.5811447Z',
        'php-error' => '2026-10-24T16:33:41.9488945Z',
        'process-synthetic' => '2026-10-24T16:33:42.2912096Z',
        'outbound-synthetic' => '2026-10-24T16:33:42.9044386Z',
        'canary' => '2026-10-24T16:33:43.4246796Z',
    ],
];
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
  <header class="topbar"><a href="/" class="brand">NINJAPAW <span>/ DEFENSE DOJO</span></a><nav aria-label="Primary"><a href="/">Story</a><a href="/walkthrough.php" aria-current="page">Walkthrough</a><a href="https://github.com/ninjapaw/php2shell-cloud-defense-dojo">GitHub</a></nav><span class="badge">PUBLIC DEMO</span></header>
  <main id="main" class="walkthrough">
    <aside class="warning"><strong>TRAINING ONLY.</strong> A fictional attack story, not an exploit runner. Real WAF behavior; synthetic PHP signals. No shell, real outbound connection, secret read, or compromise is produced.</aside>
    <section class="hero">
      <p class="eyebrow">MISSION BRIEFING / A GUIDED CODE-TO-CLOUD STORY</p>
      <h1>PHP to Proof.<br><span>The request that wanted a shell.</span></h1>
      <p class="intro">Follow Ghostpaw's five moves. <a href="/evidence/92ad189c-9a88-4403-b773-52453963e4b8">Recorded run: real logs and Defender observations</a>.</p>
      <p class="walkthrough-state"><strong>Application state: <?= escape($state) ?>.</strong> <?= $fixed ? 'Training endpoints have been removed. Read the story, but do not expect the simulator to run against this fixed application.' : 'Synthetic endpoints are available to the bounded operator simulator. Reading this guide does not run them.' ?></p>
      <p class="walkthrough-notice"><strong>Defender and Sentinel status: not queried by this page.</strong> Capabilities below are not live badges; omitted flags do not mean off. No additional app permissions are needed.</p>
      <p class="evidence-label">REAL / edge behavior &middot; SYNTHETIC / app excerpts &middot; REFERENCE / conditional detections</p>
    </section>

    <nav class="walkthrough-toc" aria-label="Walkthrough chapters">
      <h2>Your investigation route</h2>
      <ol>
        <li><a href="#briefing">Brief the team</a></li>
        <li><a href="#recorded">Inspect the recorded live run</a></li>
        <li><a href="#attack">Follow the five attack moves</a></li>
        <li><a href="#alerts">See alerts and expected results</a></li>
        <li><a href="#request">Generate one bounded run</a></li>
        <li><a href="#correlate">Build the evidence timeline</a></li>
        <li><a href="#posture">Inspect actual Defender posture</a></li>
        <li><a href="#sentinel">Compare manual hunting and analytics</a></li>
        <li><a href="#protect">Prove WAF Prevention</a></li>
        <li><a href="#remediate">Remove, verify, and clean up</a></li>
        <li><a href="#debrief">Debrief and troubleshoot</a></li>
      </ol>
      <p><a href="#components">Component map</a> / <a href="#baseline">Asset checks</a> / <a href="#containers">Private containers</a> / <a href="#glossary">Glossary</a></p>
    </nav>

    <section id="briefing" class="walkthrough-chapter" aria-labelledby="briefing-title">
      <p class="number">00 / SET THE EVIDENCE CONTRACT</p>
      <h2 id="briefing-title">Tonight, Ghostpaw knocks on the PHP application</h2>
      <p>Ghostpaw is fictional. The goal: reach execution and valuable data. Find where evidence ends and assumptions begin.</p>
      <p>Linux PHP, three fabricated records, zero runtime role grants. Front Door/WAF is public; its service tag and profile header restrict the origin.</p>
      <p class="footnote">Use an approved owned dev lab and the operator guide. Stop on ownership/HTTPS/origin failures. Expiry is not deletion; the log cap is not a budget.</p>
    </section>

    <section id="recorded" class="walkthrough-chapter" aria-labelledby="recorded-title">
      <p class="number">HISTORICAL CAPTURE / NOT LIVE</p>
      <h2 id="recorded-title">The actual recording</h2>
      <p><code><?= escape($recordedRun['id']) ?></code>: <?= escape($recordedRun['startedAt']) ?> to <?= escape($recordedRun['endedAt']) ?>; collected <?= escape($recordedRun['capturedAt']) ?> (UTC).</p>
      <p><strong>Baseline:</strong> five HTTP 200s / five synthetic records. Block/Detection is <strong>not enforced blocking</strong>. <strong>Defender:</strong> AppServices/CloudPosture/Containers Standard. The direct provider alert query succeeded and returned <code>[]</code> for the exact app/window. Four Healthy assessments are not four detections, not necessarily exclusive to paid CSPM.</p>
      <p class="walkthrough-notice"><strong>Not a Defender-disabled control run.</strong> Source logs are independently available. References are not fired alerts; missing alerts are not proof of safety. Provenance: recording link above.</p>
    </section>

    <section id="attack" class="walkthrough-chapter" aria-labelledby="attack-title">
      <p class="number">01 / FOLLOW THE ATTACK STORY</p>
      <h2 id="attack-title">Five moves, two investigation views</h2>
      <p>Intent, raw clues, conditional Defender result. Story order is not a detection or ingestion timetable.</p>
      <nav class="attack-map" aria-label="Fictional attack chain"><ol>
        <?php foreach ($moves as $move): ?>
        <li><a href="#move-<?= escape($move['signal']) ?>"><?= escape($move['title']) ?></a></li>
        <?php endforeach; ?>
      </ol></nav>
      <?php foreach ($moves as $index => $move): ?>
      <article id="move-<?= escape($move['signal']) ?>" class="attack-step" data-signal="<?= escape($move['signal']) ?>" aria-labelledby="title-<?= escape($move['signal']) ?>">
        <p class="number">MOVE <?= $index + 1 ?> / <?= escape($move['signal']) ?></p>
        <h3 id="title-<?= escape($move['signal']) ?>"><?= escape($move['title']) ?></h3>
        <p class="attack-intent"><strong>Ghostpaw's move:</strong> <?= escape($move['intent']) ?></p>
        <div class="walkthrough-compare">
          <article class="walkthrough-without">
            <p class="evidence-label">WITHOUT WORKLOAD DEFENDER / RAW CLUES</p>
            <h4>What the analyst can see</h4>
            <p><?= escape($move['without']) ?></p>
            <details open><summary>Actual ingested log from the recorded run</summary>
              <p class="footnote" data-recorded-http="200">HTTP 200 / historical capture.</p>
              <pre data-recorded-signal="<?= escape($move['signal']) ?>"><code><?= escape(json_encode([
                  'Utc' => $recordedRun['applicationUtc'][$move['signal']],
                  'Signal' => $move['signal'],
                  'Synthetic' => true,
                  'EvidenceKind' => 'synthetic-application-log',
              ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR)) ?></code></pre>
              <?php if ($move['signal'] === 'request'): ?>
              <p>Captured WAF marker:</p>
              <pre data-recorded-waf><code><?= escape(json_encode([
                  'Utc' => '2026-10-24T16:33:41.0000000Z',
                  'Rule' => 'DojoBenignMarker',
                  'Action' => 'Block',
                  'WafMode' => 'detection',
              ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR)) ?></code></pre>
              <?php endif; ?>
            </details>
          </article>
          <article class="walkthrough-with">
            <p class="evidence-label">WITH SUPPORTED DEFENDER / CONDITIONAL RESULT</p>
            <div class="alert-preview"><span class="evidence-label">DETECTION REFERENCE / NOT OBSERVED</span><h4><?= escape($move['category']) ?></h4></div>
            <p><?= escape($move['with']) ?></p>
            <p class="alert-caveat">Category reference, not a fired alert. Validate actual evidence.</p>
          </article>
        </div>
        <p><strong>Break the chain:</strong> <?= escape($move['control']) ?></p>
      </article>
      <?php endforeach; ?>
      <p><a href="https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-app-service">App Service alert reference</a>: verify Linux/detector support. No fixed names, CVE coverage, or canary detector are asserted.</p>
    </section>

    <section id="alerts" class="walkthrough-chapter" aria-labelledby="alerts-title">
      <p class="number">02 / WHAT SHOULD APPEAR?</p>
      <h2 id="alerts-title">The alert queue is not the log stream</h2>
      <div class="table-wrap" role="region" aria-label="Alerts and expected results by protection profile" tabindex="0">
        <table>
          <caption>Expected outcomes, not live alert counts. Missing evidence is not proof of safety.</caption>
          <thead><tr><th scope="col">Profile</th><th scope="col">This safe replay</th><th scope="col">What not to expect</th></tr></thead>
          <tbody>
            <tr><th scope="row">Without optional Defender/Sentinel</th><td>WAF records and synthetic app logs when delivered; manual KQL.</td><td>No native Defender or scheduled Sentinel alert.</td></tr>
            <tr><th scope="row">With paid Defender CSPM</th><td>Actual supported posture/graph results, if any.</td><td>A CSPM-generated shell alert, guaranteed CVE finding, or attack path.</td></tr>
            <tr><th scope="row">With Defender for App Service</th><td>Same harmless fixtures; investigate any independently observed supported detection.</td><td>A guaranteed alert from a simulated process, connection, or ledger read.</td></tr>
            <tr><th scope="row">With Sentinel only</th><td>Rule installed disabled.</td><td>Scheduled evaluation or an incident.</td></tr>
            <tr><th scope="row">With Sentinel + analytics</th><td>Possible Informational synthetic correlation alert when ingested evidence matches.</td><td>A Defender detection or an automatically created incident.</td></tr>
          </tbody>
        </table>
      </div>
      <p>Defender for Cloud &gt; Security alerts: filter asset/time; save returned IDs, titles, severity, evidence, status. Posture is separate. Never fill an empty queue with reference cards.</p>
    </section>

    <section id="request" class="walkthrough-chapter" aria-labelledby="request-title">
      <h2 id="request-title">Show the moves without performing an exploit</h2>
      <pre><code>bash scripts/dojo.sh simulate --environment dev --yes</code></pre>
      <p>Validate first; five benign requests share a new UUIDv4. Only the first carries <code>dojoProbe=waf-marker</code>. Save that run/UTC window.</p>
      <p class="walkthrough-check"><strong>Detection:</strong> five HTTP 200s. WAF evaluates the marker; PHP emits fixtures. No command, payload, arbitrary destination, or browser run control is provided.</p>
    </section>

    <section id="correlate" class="walkthrough-chapter" aria-labelledby="correlate-title">
      <h2 id="correlate-title">Build the evidence timeline</h2>
      <p>In workspace Logs, set <code>RunIdFilter</code> and UTC window. WAF records use <code>AzureDiagnostics</code>; PHP events use <code>AppServiceConsoleLogs</code>. Run <code>detections/waf-requests.kql</code> and <code>correlation.kql</code>, replacing <code>__APP_RESOURCE_ID__</code>.</p>
      <p>Check rule/action, request/reference, resource/time, <code>synthetic: true</code>. No <code>DeviceProcessEvents</code>/<code>DeviceNetworkEvents</code>. Ingestion does not make fixtures real.</p>
    </section>

    <section id="components" class="walkthrough-chapter" aria-labelledby="components-title">
      <h2 id="components-title">Choose the right protection layer</h2>
      <p>Foundational CSPM: free recommendations. Paid CSPM: supported graph/paths. Serverless protection is separate; pricing is not scanning. App Service is not MDE. Verify plans/support in Environment settings; <strong>incident creation is disabled</strong>.</p>
    </section>

    <section id="baseline" class="walkthrough-chapter" aria-labelledby="baseline-title">
      <h2 id="baseline-title">Validate before replaying</h2>
      <p>Read <a href="/health.php">health JSON</a>; run <code>plan</code>, <code>doctor</code>, <code>validate</code>. Origin must stay 403 even with copied FDID. No extra app roles.</p>
    </section>

    <section id="posture" class="walkthrough-chapter" aria-labelledby="posture-title">
      <p class="number">04 / REVIEW THE ACTUAL RISK CONTEXT</p>
      <h2 id="posture-title">Ask Defender what it observed, not what the slide needs</h2>
      <pre><code>bash scripts/dojo.sh investigate --environment dev</code></pre>
      <p><strong>Without paid Defender CSPM:</strong> configuration/recommendations. <strong>With paid Defender CSPM:</strong> actual graph/paths. Empty is not clearance; CVE keywords are not findings.</p>
      <p><code>--enable-defender-cspm</code> is billable subscription-wide Standard, not other plans. No recommendation export is configured.</p>
    </section>

    <section id="sentinel" class="walkthrough-chapter" aria-labelledby="sentinel-title">
      <p class="number">05 / FROM MANUAL HUNT TO OPTIONAL ANALYTICS</p>
      <h2 id="sentinel-title">Correlation is not automatically an incident</h2>
      <p>Hunt manually without Sentinel. <code>--enable-sentinel</code> installs a disabled rule; <code>--enable-analytics</code> additionally enables evaluation. Review costs and plan/deploy flags.</p>
      <div class="alert-preview"><span class="evidence-label">CONFIGURED RULE / NOT AN OBSERVED ALERT</span><h3>PHP to Proof - SYNTHETIC multi-signal training correlation</h3><p>Severity: Informational. Source: Sentinel scheduled analytics, not Defender. Incident creation: disabled.</p></div>
      <p>15-minute evaluation / one-hour window: WAF marker and at least two distinct synthetic app signals, same run, recent ingestion. Late data can miss; matches repeat. No timing guarantee. <code>createIncident: false</code>; no connector/playbook.</p>
    </section>

    <section id="protect" class="walkthrough-chapter" aria-labelledby="protect-title">
      <p class="number">06 / ENFORCE AND RE-TEST</p>
      <h2 id="protect-title">Make one deliberate prevention change</h2>
      <pre><code>bash scripts/dojo.sh protect --environment dev --yes
bash scripts/dojo.sh simulate --environment dev --yes</code></pre>
      <p class="walkthrough-check"><strong>Prevention:</strong> marker 403, four other signals 200. The marker never reaches PHP; normal traffic must work, origin stays 403.</p>
      <p>WAF, not Defender, causes the block. The custom marker is not managed-rule CVE coverage.</p>
    </section>

    <section id="remediate" class="walkthrough-chapter" aria-labelledby="remediate-title">
      <p class="number">07 / REDUCE, VERIFY, AND CLEAN UP</p>
      <h2 id="remediate-title">Remove the training surface, not just the alert</h2>
      <pre><code>bash scripts/dojo.sh remediate --environment dev --yes
bash scripts/dojo.sh validate --environment dev</code></pre>
      <p>Fixed state: all five signals 404 <strong>without the WAF marker</strong>; marked 403 alone proves nothing. Homepage/health still work. <code>simulate</code> refuses fixed; repair preserves fixed/Prevention/expiry, not a verified CVE fix.</p>
      <p>Findings need patch/assessment evidence. Teardown requires exact-owned-group confirmation; remove its CNAME before releasing the hostname. Review DNS/shared plans/private AKS separately.</p>
    </section>

    <section id="containers" class="walkthrough-chapter" aria-labelledby="containers-title">
      <p class="number">OPTIONAL ADVANCED TRACK / A DIFFERENT LAB</p>
      <h2 id="containers-title">Want real affected-versus-fixed image evidence?</h2>
      <p><code>docs/container-lab.md</code>: private affected/fixed images, existing plans/sensors, verified findings. No exploit/public ingress/guaranteed alert. Separate costs/teardown.</p>
    </section>

    <section id="debrief" class="walkthrough-chapter" aria-labelledby="debrief-title">
      <p class="number">08 / DEBRIEF</p>
      <h2 id="debrief-title">What should you leave with?</h2>
      <p>Save asset/run/UTC, WAF action, fixtures, real finding IDs. Verify isolation, unmarked fixed 404, ingestion, cleanup. Guide: <code>docs/walkthrough.md</code>.</p>
    </section>

    <section id="glossary" class="walkthrough-chapter" aria-labelledby="glossary-title">
      <h2 id="glossary-title">Plain-language glossary</h2>
      <p>Log / alert / incident: record / detector conclusion / grouped case. Synthetic: fabricated, even if ingested.</p>
      <p><a href="/">Return to the story</a> / <a href="#attack">Follow Ghostpaw again</a></p>
    </section>
  </main>
  <footer>INDEPENDENT COMMUNITY PROJECT / NOT A MICROSOFT PRODUCT OR ENDORSEMENT <span>OBSERVE. LABEL. CORROBORATE. VERIFY.</span></footer>
</body>
</html>
