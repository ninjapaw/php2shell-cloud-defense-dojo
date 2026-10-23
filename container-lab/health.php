<?php
declare(strict_types=1);
require_once __DIR__ . '/lab.php';
allow_read_only();
if ($_GET !== []) {
    json_response(['error' => 'This endpoint does not accept input.'], 400);
}
$variant = getenv('LAB_VARIANT');
$expected = getenv('PHP_VERSION_EXPECTED');
if (!in_array($variant, ['vulnerable', 'fixed'], true)
    || !in_array($expected, ['8.4.26', '8.4.27'], true)
    || ($variant === 'vulnerable') !== ($expected === '8.4.26')) {
    error_log('DOJO_CONFIGURATION_ERROR: invalid container comparison configuration');
    json_response(['error' => 'Container comparison configuration is invalid.'], 503);
}
$matches = PHP_VERSION === $expected && PHP_SAPI === 'apache2handler';
json_response([
    'scenario' => 'php2shell-container-lab',
    'environment' => 'dev',
    'variant' => $variant,
    'phpVersion' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'expectedVersion' => $expected,
    'matchesExpectedRuntime' => $matches,
    'affectedUpstreamVersion' => $variant === 'vulnerable',
    'evidenceKind' => 'observed-runtime-version-not-proof-of-compromise',
], $matches ? 200 : 503);
