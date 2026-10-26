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
$chapters = [['id' => 'briefing', 'title' => 'Brief the team']];
foreach ($moves as $move) {
    $chapters[] = ['id' => 'move-' . $move['signal'], 'title' => $move['title']];
}
array_push($chapters,
    ['id' => 'recorded', 'title' => 'Investigate the evidence'],
    ['id' => 'protect', 'title' => 'Prevent the next request'],
    ['id' => 'remediate', 'title' => 'Resolve and verify'],
    ['id' => 'debrief', 'title' => 'Close the case'],
);

function walkthrough_start(int $index, array $chapters): void {
    $chapter = $chapters[$index];
    $titleId = str_starts_with($chapter['id'], 'move-') ? 'title-' . substr($chapter['id'], 5) : $chapter['id'] . '-title';
    ?>
    <section id="<?= escape($chapter['id']) ?>" class="walkthrough-chapter" tabindex="-1" aria-labelledby="<?= escape($titleId) ?>">
      <p class="number">STEP <?= $index + 1 ?> OF <?= count($chapters) ?></p>
      <progress class="walkthrough-progress" value="<?= $index + 1 ?>" max="<?= count($chapters) ?>" aria-label="Story progress"><?= $index + 1 ?> / <?= count($chapters) ?></progress>
      <h2 id="<?= escape($titleId) ?>"><?= escape($chapter['title']) ?></h2>
    <?php
}

function walkthrough_end(int $index, array $chapters): void {
    ?>
      <nav class="walkthrough-controls" aria-label="<?= escape($chapters[$index]['title']) ?> navigation">
        <?php if ($index > 0): ?><a href="#<?= escape($chapters[$index - 1]['id']) ?>" rel="prev">Previous step</a><?php else: ?><span aria-disabled="true">Previous step</span><?php endif; ?>
        <span><?= $index + 1 ?> / <?= count($chapters) ?></span>
        <?php if ($index < count($chapters) - 1): ?><a class="guide-link" href="#<?= escape($chapters[$index + 1]['id']) ?>" rel="next">Next step</a><?php else: ?><a class="guide-link" href="#briefing">Restart story</a><?php endif; ?>
      </nav>
    </section>
    <?php
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PHP to Proof | Guided Walkthrough</title>
  <meta name="description" content="Ghostpaw's PHP trail in ten read-only cards: logs, Defender, prevention and resolution.">
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <a class="skip-link" href="#main">Skip to main content</a>
  <header class="topbar"><a href="/" class="brand">NINJAPAW <span>/ DEFENSE DOJO</span></a><nav aria-label="Primary"><a href="/">Story</a><a href="/walkthrough.php" aria-current="page">Walkthrough</a><a href="https://github.com/ninjapaw/php2shell-cloud-defense-dojo">GitHub</a><a class="badge" href="https://php2proof.ninjapaws.org/evidence/deploy">Deploy to Azure</a></nav><span class="badge">PUBLIC DEMO</span></header>
  <main id="main" class="walkthrough">
    <aside class="warning"><strong>TRAINING ONLY.</strong> A fictional attack story, not an exploit runner. Real WAF behavior; synthetic PHP signals. No shell, real outbound connection, secret read, or compromise is produced.</aside>
    <section class="hero">
      <p class="eyebrow">PHP TO PROOF / GUIDED STORY</p>
      <h1>The request that wanted a shell.</h1>
      <p class="intro">Follow Ghostpaw one card at a time. Expand the evidence when you need it.</p>
    </section>

    <nav class="walkthrough-toc" aria-label="Walkthrough chapters">
      <details><summary>Jump to a step</summary>
        <ol><?php foreach ($chapters as $chapter): ?><li><a href="#<?= escape($chapter['id']) ?>"><?= escape($chapter['title']) ?></a></li><?php endforeach; ?></ol>
      </details>
      <a href="#all-steps">Read all steps</a>
    </nav>

    <div id="all-steps" tabindex="-1">
    <?php walkthrough_start(0, $chapters); ?>
      <p>Ghostpaw is fictional. The goal: reach execution and valuable data. Find where evidence ends and assumptions begin.</p>
      <p>Linux PHP, three fabricated records, zero runtime role grants. Front Door/WAF is public; its service tag and profile header restrict the origin.</p>
      <p class="walkthrough-state"><strong>Application state: <?= escape($state) ?>.</strong> <?= $fixed ? 'Training endpoints have been removed. Read the story, but do not expect the simulator to run against this fixed application.' : 'Reading this guide does not run the synthetic endpoints.' ?></p>
      <p class="evidence-label">REAL / edge behavior &middot; SYNTHETIC / app excerpts &middot; REFERENCE / conditional detections</p>
      <details><summary>Prepare your own lab</summary>
        <h3 id="baseline"><span id="baseline-title">Validate before replaying</span></h3>
        <p>Use an approved owned dev lab. Read <a href="/health.php">health JSON</a>; run <code>plan</code>, <code>doctor</code>, <code>validate</code>. Origin must stay 403 even with copied FDID. No extra app roles. Stop on ownership/HTTPS/origin failures.</p>
        <h3 id="request"><span id="request-title">Generate a bounded run</span></h3>
        <p>Set <code>DOJO_SUFFIX</code> and <code>AZURE_SUBSCRIPTION_ID</code> first.</p>
        <pre><code>bash scripts/dojo.sh simulate --environment dev --yes</code></pre>
        <p>Five benign requests share a new UUIDv4; only the first carries <code>dojoProbe=waf-marker</code>. Save the run/UTC window. Detection: five HTTP 200s. No command, payload, arbitrary destination, or browser run control.</p>
        <p>Expiry is not deletion; the log cap is not a budget.</p>
      </details>
    <?php walkthrough_end(0, $chapters); ?>

      <?php foreach ($moves as $index => $move): ?>
      <?php walkthrough_start($index + 1, $chapters); ?>
      <article class="attack-step" data-signal="<?= escape($move['signal']) ?>" aria-label="Fictional attack chain">
        <?php if ($index === 0): ?><p id="attack"><span id="attack-title">Story order is not a detection or ingestion timetable.</span></p><?php endif; ?>
        <p class="attack-intent"><strong>Ghostpaw's move:</strong> <?= escape($move['intent']) ?></p>
        <div class="walkthrough-compare">
          <article class="walkthrough-without">
            <p class="evidence-label">WITHOUT WORKLOAD DEFENDER / RAW CLUES</p>
            <h3>What the analyst can see</h3>
            <p><?= escape($move['without']) ?></p>
            <details><summary>Actual ingested log from the recorded run</summary>
              <p class="footnote" data-recorded-http="200">HTTP 200 / historical capture.</p>
              <pre data-recorded-signal="<?= escape($move['signal']) ?>"><code><?= escape(json_encode([
                  'Utc' => $recordedRun['applicationUtc'][$move['signal']],
                  'Signal' => $move['signal'],
                  'Synthetic' => true,
                  'EvidenceKind' => 'synthetic-application-log',
              ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR)) ?></code></pre>
              <?php if ($move['signal'] === 'request'): ?>
              <p>Captured WAF marker (Block/Detection, not enforced blocking):</p>
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
            <div class="alert-preview"><span class="evidence-label">DETECTION REFERENCE / NOT OBSERVED</span><h3><?= escape($move['category']) ?></h3></div>
            <p><?= escape($move['with']) ?></p>
            <p class="alert-caveat">No provider alerts in this run. Category reference, not a fired alert.</p>
          </article>
        </div>
        <p><strong>Break the chain:</strong> <?= escape($move['control']) ?></p>
        <details><summary>Check the detector reference</summary>
          <p><a href="https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-app-service">App Service alert reference</a>: verify Linux/detector support. No fixed names, CVE coverage, or canary detector are asserted.</p>
        </details>
      </article>
      <?php walkthrough_end($index + 1, $chapters); ?>
      <?php endforeach; ?>

    <?php walkthrough_start(6, $chapters); ?>
      <p class="number">HISTORICAL CAPTURE / NOT LIVE</p>
      <p><a href="https://php2proof.ninjapaws.org/evidence/92ad189c-9a88-4403-b773-52453963e4b8">Historical reference capture</a>, not your new deployment's logs.</p>
      <p><code><?= escape($recordedRun['id']) ?></code>: <?= escape($recordedRun['startedAt']) ?> to <?= escape($recordedRun['endedAt']) ?>; collected <?= escape($recordedRun['capturedAt']) ?> (UTC).</p>
      <p><strong>Baseline:</strong> five HTTP 200s / five synthetic records. Block/Detection is <strong>not enforced blocking</strong>. <strong>Defender:</strong> AppServices/CloudPosture/Containers read Standard after the run; run-time plan state is unknown. The direct provider alert query succeeded and returned <code>[]</code> for the exact app/window. Four Healthy assessments are not four detections, not necessarily exclusive to paid CSPM.</p>
      <p><strong>Not a Defender-disabled control run.</strong> References are not fired alerts; missing alerts are not proof of safety.</p>
      <details><summary>Alerts and expected results</summary>
      <h3 id="alerts"><span id="alerts-title">The alert queue is not the log stream</span></h3>
      <div class="table-wrap" role="region" aria-label="Alerts and expected results by protection profile" tabindex="0">
        <table>
          <caption>Expected outcomes, not live alert counts. Missing evidence is not proof of safety.</caption>
          <thead><tr><th scope="col">Profile</th><th scope="col">This safe replay</th><th scope="col">What not to expect</th></tr></thead>
          <tbody>
            <tr><th scope="row">Without optional Defender/Sentinel</th><td>Delivered WAF/app logs; manual KQL.</td><td>No Defender or scheduled Sentinel alert.</td></tr>
            <tr><th scope="row">With paid Defender CSPM</th><td>Actual supported posture/graph results.</td><td>No guaranteed CVE finding, attack path or shell alert.</td></tr>
            <tr><th scope="row">With Defender for App Service</th><td>Fixtures; inspect independently observed detections.</td><td>No guaranteed alert from synthetic activity.</td></tr>
            <tr><th scope="row">With Sentinel only</th><td>Rule installed disabled.</td><td>Scheduled evaluation or an incident.</td></tr>
            <tr><th scope="row">With Sentinel + analytics</th><td>Possible Informational synthetic correlation when logs match.</td><td>Not a Defender detection or automatic incident.</td></tr>
          </tbody>
        </table>
      </div>
      <p>Defender for Cloud &gt; Security alerts: filter asset/time; save IDs, titles, severity, evidence and status. Posture is separate; references never fill an empty queue.</p>
      </details>
      <details><summary>Queries, timeline and hunting results</summary>
      <h3 id="correlate"><span id="correlate-title">Build the evidence timeline</span></h3>
      <p>In workspace Logs, set <code>RunIdFilter</code>; queries look back 1 h. WAF records use <code>AzureDiagnostics</code>; PHP events use <code>AppServiceConsoleLogs</code>. Run <code>detections/waf-requests.kql</code> and <code>correlation.kql</code>, replacing <code>__APP_RESOURCE_ID__</code>.</p>
      <p>Check rule/action, request/reference, resource/time, <code>synthetic: true</code>. No <code>DeviceProcessEvents</code>/<code>DeviceNetworkEvents</code>. Ingestion does not make fixtures real.</p>
      <p><a href="https://php2proof.ninjapaws.org/evidence/hunting">Open all hunting queries, captured results and additional-value walkthroughs</a> (central historical reference).</p>
      </details>
      <details><summary>Defender posture and protection layers</summary>
      <h3 id="posture"><span id="posture-title">Review the actual risk context</span></h3>
      <pre><code>bash scripts/dojo.sh investigate --environment dev</code></pre>
      <p><strong>Without paid Defender CSPM:</strong> configuration/recommendations. <strong>With paid Defender CSPM:</strong> actual graph/paths. Empty is not clearance; CVE keywords are not findings.</p>
      <p><code>--enable-defender-cspm</code> is billable subscription-wide Standard, not other plans. No recommendation export is configured.</p>
      <h3 id="components"><span id="components-title">Choose the right protection layer</span></h3>
      <p>Foundational CSPM: free recommendations. Paid CSPM: supported graph/paths. Serverless protection is separate; pricing is not scanning. App Service is not MDE. Verify plans/support in Environment settings; <strong>incident creation is disabled</strong>.</p>
      <p class="walkthrough-notice"><strong>Defender and Sentinel status: not queried by this page.</strong> Omitted flags do not mean off; no extra app permissions are needed.</p>
      </details>
      <details><summary>Optional Sentinel analytics</summary>
      <h3 id="sentinel"><span id="sentinel-title">Correlation is not automatically an incident</span></h3>
      <p>Hunt manually without Sentinel. <code>--enable-sentinel</code> installs a disabled rule; <code>--enable-analytics</code> additionally enables evaluation. Review costs and plan/deploy flags.</p>
      <div class="alert-preview"><span class="evidence-label">CONFIGURED RULE / NOT AN OBSERVED ALERT</span><h3>PHP to Proof - SYNTHETIC multi-signal training correlation</h3><p>Severity: Informational. Source: Sentinel scheduled analytics, not Defender. Incident creation: disabled.</p></div>
      <p>15-minute evaluation / one-hour window: WAF marker and at least two distinct synthetic app signals, same run, recent ingestion. Late data can miss; matches repeat. No timing guarantee. <code>createIncident: false</code>; no connector/playbook.</p>
      </details>
    <?php walkthrough_end(6, $chapters); ?>

    <?php walkthrough_start(7, $chapters); ?>
      <p>Expected after an approved change in your own lab, not a captured after-state:</p>
      <pre><code>bash scripts/dojo.sh protect --environment dev --yes
bash scripts/dojo.sh simulate --environment dev --yes</code></pre>
      <p class="walkthrough-check"><strong>Prevention:</strong> marker 403, four other signals 200. Normal traffic must work; origin stays 403.</p>
      <p><a href="https://php2proof.ninjapaws.org/evidence/response">Official response and scripts</a>: stage three request rules in Log first. Response rule 99006001 has no WAF hits/logs. WAF mitigation is not a PHP patch.</p>
    <?php walkthrough_end(7, $chapters); ?>

    <?php walkthrough_start(8, $chapters); ?>
      <pre><code>bash scripts/dojo.sh remediate --environment dev --yes
bash scripts/dojo.sh validate --environment dev</code></pre>
      <p>Fixed: five signals 404 <strong>without the WAF marker</strong>; health 200, origin 403. Repair preserves fixed/Prevention/expiry. Fixture removal is not a PHP patch.</p>
      <p><a href="https://php2proof.ninjapaws.org/evidence/response#response-closure">Resolution script and closure checks</a>: verify running PHP 8.4.27+, rebuild images, inspect findings. Approved window required; no after-state is claimed.</p>
    <?php walkthrough_end(8, $chapters); ?>

    <?php walkthrough_start(9, $chapters); ?>
      <p>Save asset/run/UTC, WAF action, fixtures and real finding IDs. Verify isolation, unmarked fixed 404, ingestion and cleanup. Guide: <code>docs/walkthrough.md</code>.</p>
      <p>Use Uninstall in the deployment wizard when finished. Expiry is not deletion.</p>
      <details><summary>Optional private container lab</summary>
      <h3 id="containers"><span id="containers-title">A different lab, with real image evidence</span></h3>
      <p><code>docs/container-lab.md</code>: private affected/fixed images, existing plans/sensors, verified findings. No exploit/public ingress/guaranteed alert. Separate costs/teardown.</p>
      </details>
      <details><summary>Plain-language glossary</summary>
      <h3 id="glossary"><span id="glossary-title">Logs, alerts and incidents</span></h3>
      <p>Log / alert / incident: record / detector conclusion / grouped case. Synthetic: fabricated, even if ingested.</p>
      </details>
      <p><a href="/">Return to the story</a> / <a href="#attack">Follow Ghostpaw again</a></p>
    <?php walkthrough_end(9, $chapters); ?>
    </div>
  </main>
  <footer>INDEPENDENT COMMUNITY PROJECT / NOT A MICROSOFT PRODUCT OR ENDORSEMENT <span>OBSERVE. LABEL. CORROBORATE. VERIFY.</span></footer>
</body>
</html>
