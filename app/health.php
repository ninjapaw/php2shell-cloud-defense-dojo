<?php
declare(strict_types=1);
require_once __DIR__ . '/lab.php';

allow_read_only();
$state = lab_state();
json_response([
    'scenario' => DOJO_SCENARIO,
    'environment' => 'dev',
    'state' => $state,
    'phpVersion' => PHP_VERSION,
    'resourceId' => getenv('LAB_RESOURCE_ID') ?: 'local://php2shell',
    'syntheticEndpointsEnabled' => $state === 'training',
]);
