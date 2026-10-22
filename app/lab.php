<?php
declare(strict_types=1);

const DOJO_SCENARIO = 'php2shell-cloud-defense-dojo';

function lab_state(): string
{
    $environment = getenv('LAB_ENVIRONMENT');
    $state = getenv('LAB_STATE');
    $environment = $environment === false ? 'dev' : $environment;
    $state = $state === false ? 'training' : $state;
    if ($environment !== 'dev' || !in_array($state, ['training', 'fixed'], true)) {
        error_log('DOJO_CONFIGURATION_ERROR: invalid environment or state');
        json_response(['error' => 'Training configuration is invalid.'], 503);
    }
    return $state;
}

function security_headers(): void
{
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
}

function json_response(array $data, int $status = 200): never
{
    security_headers();
    header('Content-Type: application/json; charset=utf-8');
    http_response_code($status);
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') {
        echo json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
    exit;
}

function allow_read_only(): void
{
    if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
        header('Allow: GET, HEAD');
        json_response(['error' => 'Only bounded read-only requests are supported.'], 405);
    }
}

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
