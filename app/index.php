<?php
declare(strict_types=1);
require_once __DIR__ . '/lab.php';

allow_read_only();
$state = lab_state();
$allowedKeys = ['signal', 'runId', 'dojoProbe'];
foreach (array_keys($_GET) as $key) {
    if (!in_array($key, $allowedKeys, true) || !is_string($_GET[$key])) {
        json_response(['error' => 'Unsupported training input.'], 400);
    }
}

if (isset($_GET['signal'])) {
    if ($state === 'fixed') {
        json_response(['error' => 'Synthetic scenario endpoints were removed by remediation.'], 404);
    }
    $signal = $_GET['signal'];
    $signals = ['request', 'php-error', 'process-synthetic', 'outbound-synthetic', 'canary'];
    $runId = $_GET['runId'] ?? '';
    if (!in_array($signal, $signals, true)
        || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D', $runId)
        || (isset($_GET['dojoProbe']) && $_GET['dojoProbe'] !== 'waf-marker')) {
        json_response(['error' => 'Use a supported signal, a UUIDv4 runId, and only the benign WAF marker.'], 400);
    }
    $event = [
        'schemaVersion' => 1,
        'scenario' => DOJO_SCENARIO,
        'timestamp' => gmdate('c'),
        'synthetic' => true,
        'signal' => $signal,
        'runId' => $runId,
        'resourceId' => getenv('LAB_RESOURCE_ID') ?: 'local://php2shell',
        'hostname' => gethostname() ?: 'unknown',
        'clientIp' => $_SERVER['HTTP_X_AZURE_CLIENTIP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'identity' => 'unprivileged-training-application',
        'evidenceKind' => 'synthetic-application-log',
        'message' => match ($signal) {
            'request' => 'Benign correlation request. No vulnerability was exercised.',
            'php-error' => 'SIMULATED unusual PHP error. No exception or exploit was executed.',
            'process-synthetic' => 'SIMULATED unexpected child process. No process was started.',
            'outbound-synthetic' => 'SIMULATED outbound connection. No network connection was made.',
            'canary' => 'SIMULATED canary read from a constant fixture. No Azure data-plane access occurred.',
        },
    ];
    if ($signal === 'canary') {
        $event['canary'] = ['id' => 'synthetic://php2shell/ledger', 'classification' => 'fabricated-training-data', 'records' => 3];
    }
    error_log('DOJO_EVENT ' . json_encode($event, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    json_response($event);
}
if ($_GET !== []) {
    json_response(['error' => 'Scenario inputs require a supported signal and runId.'], 400);
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
  <title>PHP to Proof | Code-to-Cloud Defense Story</title>
  <meta name="description" content="PHP to Proof: follow a defensive PHP2Shell investigation from cloud exposure to real WAF evidence, synthetic application signals, and verified remediation.">
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <a class="skip-link" href="#main">Skip to main content</a>
  <header class="topbar"><a href="/" class="brand">NINJAPAW <span>/ DEFENSE DOJO</span></a><nav aria-label="Primary"><a href="/" aria-current="page">Story</a><a href="/walkthrough.php">Walkthrough</a><a href="https://github.com/ninjapaw/php2shell-cloud-defense-dojo">GitHub</a><a class="badge" href="https://php2proof.ninjapaws.org/evidence/deploy">Deploy to Azure</a></nav><span class="badge">PUBLIC DEMO</span></header>
  <main id="main">
    <aside class="warning"><strong>TRAINING ONLY.</strong> Isolated, authorized subscriptions. Fabricated data. No exploit, shell, or real compromise is demonstrated.</aside>
    <section class="hero">
      <p class="eyebrow">A CODE-TO-CLOUD DEFENSE STORY / INVESTIGATION 01</p>
      <h1>PHP to Proof.<br><span>Evidence tells the story.</span></h1>
      <p class="intro">A fictional attack story, not an exploit runner. Real WAF behavior; synthetic PHP signals.</p>
      <p><a class="guide-link" href="/walkthrough.php">Start the guided walkthrough <span aria-hidden="true">&rarr;</span></a></p>
      <div class="status <?= $fixed ? 'fixed' : '' ?>"><span class="dot"></span><?= $fixed ? 'FIXED STATE / TRAINING SURFACES REMOVED' : 'TRAINING STATE / SYNTHETIC SIGNALS AVAILABLE' ?></div>
    </section>
    <section class="cards" aria-label="Investigation boundaries">
      <article><span class="number">01 / POSTURE</span><h2>Discover the asset</h2><p>Use Defender CSPM and Cloud Security Explorer to inspect the actual deployed resource. Findings and attack paths are not guaranteed.</p><span class="label">OBSERVE, DO NOT ASSUME</span></article>
      <article><span class="number">02 / EDGE</span><h2>Understand the request</h2><p>A benign query marker demonstrates WAF Detection, then Prevention. Its custom rule is not evidence of CVE protection.</p><span class="label">REAL WAF / HARMLESS INPUT</span></article>
      <article><span class="number">03 / CORRELATION</span><h2>Separate fact from fiction</h2><p>PHP errors, child-process shapes, outbound shapes, and canary reads are labelled synthetic logs. None execute the described behavior.</p><span class="label">SYNTHETIC, NOT COMPROMISE</span></article>
    </section>
    <section class="workbench">
      <div><p class="eyebrow">THE INVESTIGATOR'S NOTEBOOK</p><h2>One run. Multiple pivots.</h2><p>Run the guarded simulator from your operator terminal. Keep its run ID and UTC time window, then correlate WAF and application records in the lab workspace.</p><code>simulate --environment dev --suffix &lt;your-suffix&gt; --yes</code></div>
      <dl><dt>Application</dt><dd>Harmless PHP training workload</dd><dt>Data</dt><dd>3 fabricated ledger records</dd><dt>Runtime identity</dt><dd>No Azure role grants required</dd><dt>Scenario state</dt><dd><?= escape($state) ?></dd><dt>Evidence boundary</dt><dd>No shell, egress, or real canary access</dd></dl>
    </section>
    <section class="journey"><p class="eyebrow">THE DEFENDER'S LOOP</p><h2>Discover. Correlate. Reduce. Verify.</h2><ol><li>Discover the asset and inspect exposure</li><li>Review available assessments and attack paths</li><li>Generate five bounded benign requests</li><li>Correlate real WAF and synthetic app evidence</li><li>Validate WAF Prevention</li><li>Remove training surfaces and verify closure</li></ol></section>
    <p class="footnote">CVE-2026-109618 and CVE-2026-109619 are supplied investigation search terms, not findings or claims about this PHP runtime. No assessment, runtime alert, or attack path is fabricated.</p>
  </main>
  <footer>INDEPENDENT COMMUNITY PROJECT / NOT A MICROSOFT PRODUCT OR ENDORSEMENT <span>DISPOSABLE BY DESIGN</span></footer>
</body>
</html>
