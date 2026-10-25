import reviewedImages from "../../container-lab/images.json" with { type: "json" };
import { UUID } from "./config.mjs";
import {
  CONTAINER_NAMESPACE, CONTAINER_SCENARIO, assertContainerIsolation, containerNames, containerWorkload,
} from "./container-lab.mjs";

export const PRIVATE_LIVE_LIMITS = Object.freeze({
  windowMilliseconds: 4 * 60 * 60 * 1000,
  readSeconds: 180,
  transitionSeconds: 600,
  resultBytes: 32 * 1024,
  commandBytes: 32 * 1024,
});
const SCHEMA = "php2proof-private-live/v1";
const EVIDENCE_KIND = "observed-private-administrative-action-not-exploitation";
const MARKER = "PHP2PROOF_PRIVATE_RESULT ";
const BASE_DIGESTS = Object.freeze([reviewedImages.vulnerable.source, reviewedImages.fixed.source].map((source) => source.split("@")[1]));
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const POD_NAME = /^php-runtime-[a-z0-9]{1,10}-[a-z0-9]{5}$/;
const ID_OUTPUT = /^uid=10001(?:\([a-zA-Z0-9_-]{1,32}\))? gid=10001(?:\([a-zA-Z0-9_-]{1,32}\))? groups=10001(?:\([a-zA-Z0-9_-]{1,32}\))?$/;
const SNAPSHOT_FIELDS = [
  "observedAt", "namespaceUid", "deploymentUid", "deploymentResourceVersion",
  "podName", "podUid", "image", "imageId", "healthStatus", "health", "isolationVerified",
];
const HEALTH_FIELDS = [
  "scenario", "environment", "variant", "phpVersion", "sapi", "expectedVersion",
  "matchesExpectedRuntime", "affectedUpstreamVersion", "evidenceKind",
];
const fail = (message) => { throw new Error(message); };
const matches = (expression, value) => expression.exec(value)?.[0] === value;
const freeze = (value) => {
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
};
const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;

function fields(value, required, label, optional = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(`${label} must be a plain object.`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string" || ![...required, ...optional].includes(key)
      || !Object.hasOwn(descriptors[key], "value") || !descriptors[key].enumerable)
      || required.some((key) => !Object.hasOwn(descriptors, key))) fail(`${label} has missing, unknown or accessor fields.`);
}

function uuid(value, label) {
  if (typeof value !== "string" || !matches(UUID, value) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value)) fail(`${label} must be a non-nil UUID.`);
}

function timestamp(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) fail(`${label} must be an explicit UTC timestamp.`);
  const milliseconds = Date.parse(value);
  if (!Number.isSafeInteger(milliseconds)
      || ![new Date(milliseconds).toISOString(), new Date(milliseconds).toISOString().replace(".000Z", "Z")].includes(value)) fail(`${label} is not a valid UTC timestamp.`);
  return milliseconds;
}

// Azure also emits seven-digit UTC fractions; retain them for comparisons.
function cloudTimestamp(value, label) {
  const match = typeof value === "string" && /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(?:Z|\+00:00)$/.exec(value);
  if (!match || match[0] !== value) fail(`${label} must be an explicit UTC Azure timestamp.`);
  const seconds = timestamp(`${match[1]}Z`, label);
  const fraction = match[2] === undefined ? "000000000" : match[2].padEnd(9, "0");
  return BigInt(seconds) * 1_000_000n + BigInt(fraction);
}

function clock(now) {
  if (!Number.isSafeInteger(now) || now < 0) fail("An explicit current UTC time in integer milliseconds is required.");
}

function sameResource(value, expected, label) {
  if (typeof value !== "string" || value.toLowerCase() !== expected.toLowerCase()) fail(`${label} must be the exact derived private resource ID.`);
}

// The adapter independently verifies ownership and reads the exact group's
// dojo.liveWindowId/dojo.liveWindowExpiresAt tags into marker before calling.
export function validatePrivateTarget(target, now) {
  clock(now);
  fields(target, ["subscription", "suffix", "resourceGroupId", "clusterId", "registryId", "window", "marker", "images"], "Private target");
  uuid(target.subscription, "Subscription");
  if (typeof target.suffix !== "string" || !matches(/^[a-z0-9]{4,12}$/, target.suffix)) fail("The private suffix must contain 4-12 lowercase letters/digits.");
  const names = containerNames(target);
  const groupId = `/subscriptions/${target.subscription}/resourceGroups/${names.group}`;
  sameResource(target.resourceGroupId, groupId, "Resource group");
  sameResource(target.clusterId, `${groupId}/providers/Microsoft.ContainerService/managedClusters/${names.cluster}`, "Cluster");
  sameResource(target.registryId, `${groupId}/providers/Microsoft.ContainerRegistry/registries/${names.registry}`, "Registry");
  fields(target.window, ["schemaVersion", "id", "notBefore", "expiresAt", "resourceGroup", "autoTeardown"], "Live window");
  if (target.window.schemaVersion !== 1 || target.window.resourceGroup !== names.group || target.window.autoTeardown !== true) fail("The exact private group and explicit auto-teardown intent must match the version-one live-window envelope.");
  uuid(target.window.id, "Live window ID");
  const started = timestamp(target.window.notBefore, "Live window start");
  const expires = timestamp(target.window.expiresAt, "Live window expiry");
  if (started > now || now >= expires || expires <= started || expires - started > PRIVATE_LIVE_LIMITS.windowMilliseconds) fail("A current, newly approved live window of at most four hours is required.");
  fields(target.marker, ["windowId", "expiresAt"], "Fresh private target marker");
  if (target.marker.windowId !== target.window.id || target.marker.expiresAt !== target.window.expiresAt) fail("The private target must carry the exact fresh live-window marker.");
  fields(target.images, ["affected", "fixed"], "Observed private images");
  for (const [variant, version] of [["affected", "8.4.26"], ["fixed", "8.4.27"]]) {
    const image = target.images[variant];
    fields(image, ["version", "digest", "observedAt"], `Observed ${variant} image`);
    if (image.version !== version || typeof image.digest !== "string" || !matches(DIGEST, image.digest)
        || image.digest === `sha256:${"0".repeat(64)}` || BASE_DIGESTS.includes(image.digest)) fail("Only reviewed, independently observed derived PHP image versions and non-placeholder digests are accepted.");
    const observed = timestamp(image.observedAt, `Observed ${variant} image time`);
    if (observed < started || observed > now || observed >= expires) fail("Derived image observations must belong to the current live window.");
  }
  if (target.images.affected.digest === target.images.fixed.digest) fail("Affected and fixed derived-image digests must be distinct.");
  return freeze(structuredClone(target));
}

export function privateTransitionConfirmation(target, operation, now) {
  const checked = validatePrivateTarget(target, now);
  if (!["fix", "reset"].includes(operation)) fail("Only the separate fixed-image and private training-reset actions have transition confirmations.");
  const variant = operation === "fix" ? "fixed" : "affected";
  const image = checked.images[variant];
  return `${operation === "fix" ? "FIX" : "RESET"} PRIVATE ${containerNames(checked).group} TO PHP ${image.version} ${image.digest} WINDOW ${checked.window.id}`;
}

function requestFor(target, request, now) {
  fields(request, ["operation", "operationId", "runId"], "Private operation", ["confirmation", "variant"]);
  if (!["run", "fix", "verify", "reset"].includes(request.operation)) fail("Unknown private operation; arbitrary commands are not accepted.");
  const transition = ["fix", "reset"].includes(request.operation);
  fields(request, ["operation", "operationId", "runId", transition ? "confirmation" : "variant"], "Private operation");
  uuid(request.operationId, "Operation ID");
  uuid(request.runId, "Run ID");
  if (transition) {
    if (request.confirmation !== privateTransitionConfirmation(target, request.operation, now)) fail("The exact separate private transition confirmation is required.");
  } else if (!["affected", "fixed"].includes(request.variant)
      && !(request.operation === "verify" && request.variant === "either")) fail("Only verify accepts either; Run requires one explicit affected/fixed image variant.");
  return request;
}

function layout(target, variant) {
  const registry = `${containerNames(target).registry}.azurecr.io`;
  const manifest = containerWorkload(registry, target.images[variant].digest, variant === "affected" ? "vulnerable" : "fixed");
  const deployment = manifest.items.find((item) => item.kind === "Deployment");
  assertContainerIsolation(manifest.items[0], manifest.items[1], { items: [] }, deployment.spec.template);
  if (deployment.metadata.name !== "php-runtime" || deployment.spec.template.spec.containers[0].name !== "php") fail("The reviewed private deployment layout changed; review the closed command boundary.");
  return deployment;
}

// This immutable program validates Kubernetes readbacks and the fixed loopback
// health endpoint. No request text, environment data or PHP is evaluated as code.
const INSPECT_PHP = String.raw`
function demand($condition) { if (!$condition) { throw new RuntimeException("Private observation failed."); } }
function field($value, $key) {
  demand($value instanceof stdClass && property_exists($value, $key));
  return $value->$key;
}
function exactKeys($value, $keys) {
  demand($value instanceof stdClass);
  $actual = array_keys(get_object_vars($value)); sort($actual); sort($keys); demand($actual === $keys);
}
function decode($text) {
  demand(is_string($text) && strlen($text) <= 65536);
  return json_decode($text, false, 64, JSON_THROW_ON_ERROR);
}
function subset($actual, $expected) {
  if ($expected instanceof stdClass) {
    demand($actual instanceof stdClass);
    foreach (get_object_vars($expected) as $key => $value) { subset(field($actual, $key), $value); }
  } elseif (is_array($expected)) {
    demand(is_array($actual) && count($actual) === count($expected));
    foreach ($expected as $key => $value) { subset($actual[$key], $value); }
  } else { demand($actual === $expected); }
}
function validUuid($value) { return is_string($value) && preg_match('/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/iD', $value) === 1; }
function owner($value, $kind) {
  $references = field(field($value, "metadata"), "ownerReferences"); demand(is_array($references));
  $controllers = array_values(array_filter($references, fn($item) => field($item, "controller") === true));
  demand(count($controllers) === 1 && field($controllers[0], "kind") === $kind && field($controllers[0], "apiVersion") === "apps/v1");
  return $controllers[0];
}
try {
  demand(count($argv) === 8);
  $expected = decode($argv[1]); $phase = $argv[2];
  demand(in_array($phase, ["before", "after"], true));
  demand(time() >= $expected->windowStartedEpoch && time() < $expected->windowExpiresEpoch);
  $input = stream_get_contents(STDIN, 393217);
  demand(is_string($input) && strlen($input) <= 393216);
  $resources = json_decode($input, false, 64, JSON_THROW_ON_ERROR);
  demand(is_array($resources) && count($resources) === 6);
  [$namespace, $policy, $services, $deployment, $pods, $replicasets] = $resources;
  $nsMetadata = field($namespace, "metadata");
  demand(field($nsMetadata, "name") === "php2shell-isolated");
  $labels = field($nsMetadata, "labels");
  foreach (["enforce", "audit", "warn"] as $mode) { demand(field($labels, "pod-security.kubernetes.io/" . $mode) === "restricted"); }
  demand(field($labels, "dojo.scenario") === "php2shell-container-lab");
  demand(field(field($policy, "metadata"), "name") === "deny-all" && field($policy->metadata, "namespace") === "php2shell-isolated");
  $policySpec = field($policy, "spec");
  exactKeys(field($policySpec, "podSelector"), []);
  $directions = field($policySpec, "policyTypes"); demand(is_array($directions)); sort($directions);
  demand($directions === ["Egress", "Ingress"]);
  foreach (["ingress", "egress"] as $direction) { if (property_exists($policySpec, $direction)) { demand(is_array($policySpec->$direction) && count($policySpec->$direction) === 0); } }
  demand(field($services, "items") === []);
  $metadata = field($deployment, "metadata"); $spec = field($deployment, "spec"); $status = field($deployment, "status");
  demand(field($metadata, "name") === "php-runtime" && field($metadata, "namespace") === "php2shell-isolated");
  demand(validUuid(field($metadata, "uid")) && validUuid(field($nsMetadata, "uid")));
  demand(is_string(field($metadata, "resourceVersion")) && preg_match('/\A[1-9][0-9]{0,19}\z/D', $metadata->resourceVersion) === 1);
  demand(is_int(field($metadata, "generation")) && $metadata->generation > 0 && field($status, "observedGeneration") === $metadata->generation);
  demand(field($spec, "replicas") === 1);
  foreach (["replicas", "readyReplicas", "availableReplicas", "updatedReplicas"] as $key) { demand(field($status, $key) === 1); }
  exactKeys(field(field($spec, "selector"), "matchLabels"), ["app"]);
  demand(field($spec->selector->matchLabels, "app") === "php2shell-container-lab");
  $items = field($pods, "items"); demand(is_array($items) && count($items) <= 4);
  $live = array_values(array_filter($items, fn($pod) => !property_exists(field($pod, "metadata"), "deletionTimestamp") || $pod->metadata->deletionTimestamp === null));
  demand(count($live) === 1); $pod = $live[0]; $podMetadata = field($pod, "metadata");
  $podName = field($podMetadata, "name");
  demand(is_string($podName) && preg_match('/\Aphp-runtime-[a-z0-9]{1,10}-[a-z0-9]{5}\z/D', $podName) === 1 && gethostname() === $podName);
  demand(field($podMetadata, "namespace") === "php2shell-isolated" && validUuid(field($podMetadata, "uid")));
  demand(field(field($podMetadata, "labels"), "app") === "php2shell-container-lab");
  $reference = owner($pod, "ReplicaSet"); $sets = field($replicasets, "items"); demand(is_array($sets) && count($sets) <= 8);
  $matching = array_values(array_filter($sets, fn($set) => field(field($set, "metadata"), "uid") === field($reference, "uid")));
  demand(count($matching) === 1 && field($matching[0]->metadata, "name") === field($reference, "name"));
  $deploymentOwner = owner($matching[0], "Deployment");
  demand(field($deploymentOwner, "uid") === $metadata->uid && field($deploymentOwner, "name") === "php-runtime");
  $podSpec = field($pod, "spec"); $containers = field($podSpec, "containers"); demand(is_array($containers) && count($containers) === 1);
  $image = field($containers[0], "image"); $variant = null;
  foreach (["affected", "fixed"] as $candidate) { if ($image === $expected->images->$candidate->image) { $variant = $candidate; } }
  demand($variant !== null);
  $required = $phase === "before" ? $expected->beforeVariant : $expected->afterVariant;
  demand($required === "either" || $required === $variant);
  $annotation = $variant === "affected" ? "vulnerable" : "fixed";
  demand(field(field(field($spec, "template"), "metadata")->annotations, "dojo.variant") === $annotation);
  demand(field(field($podMetadata, "annotations"), "dojo.variant") === $annotation);
  $baseline = $expected->baseline; $baseline->containers[0]->image = $image;
  subset(field($spec->template, "spec"), $baseline); subset($podSpec, $baseline);
  foreach ([$spec->template->spec, $podSpec] as $boundary) {
    foreach (["hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"] as $key) { if (property_exists($boundary, $key)) { demand($boundary->$key === false); } }
    foreach (["initContainers", "ephemeralContainers"] as $key) { if (property_exists($boundary, $key)) { demand($boundary->$key === []); } }
    $podSecurity = $boundary->securityContext;
    if (property_exists($podSecurity, "supplementalGroups")) { demand($podSecurity->supplementalGroups === [] || $podSecurity->supplementalGroups === [10001]); }
    if (property_exists($podSecurity, "sysctls")) { demand($podSecurity->sysctls === []); }
    foreach ($boundary->volumes as $volume) { foreach (["hostPath", "secret", "projected", "persistentVolumeClaim"] as $key) { demand(!property_exists($volume, $key)); } }
    $container = $boundary->containers[0]; $security = $container->securityContext;
    foreach (["command", "args", "env", "envFrom", "lifecycle", "volumeDevices"] as $key) { demand(!property_exists($container, $key)); }
    if (property_exists($security->capabilities, "add")) { demand($security->capabilities->add === []); }
    foreach (["runAsUser", "runAsGroup"] as $key) { if (property_exists($security, $key)) { demand($security->$key === 10001); } }
    if (property_exists($security, "runAsNonRoot")) { demand($security->runAsNonRoot === true); }
    if (property_exists($security, "seccompProfile")) { exactKeys($security->seccompProfile, ["type"]); demand($security->seccompProfile->type === "RuntimeDefault"); }
    if (property_exists($security, "appArmorProfile")) { exactKeys($security->appArmorProfile, ["type"]); demand($security->appArmorProfile->type === "RuntimeDefault"); }
    if (property_exists($security, "procMount")) { demand($security->procMount === "Default"); }
  }
  $podStatus = field($pod, "status"); demand(field($podStatus, "phase") === "Running");
  $containerStatuses = field($podStatus, "containerStatuses"); demand(is_array($containerStatuses) && count($containerStatuses) === 1);
  $containerStatus = $containerStatuses[0];
  demand(field($containerStatus, "name") === "php" && field($containerStatus, "ready") === true && field($containerStatus, "image") === $image);
  demand(field(field($containerStatus, "state"), "running") instanceof stdClass);
  $imageId = field($containerStatus, "imageID"); $digest = $expected->images->$variant->digest;
  demand(in_array($imageId, [$image, "docker-pullable://" . $image, "containerd://" . $digest, $digest], true));
  $context = stream_context_create(["http" => ["method" => "GET", "follow_location" => 0, "max_redirects" => 0, "timeout" => 3, "ignore_errors" => true, "header" => "Connection: close\r\n"]]);
  $body = @file_get_contents("http://127.0.0.1:8080/health.php", false, $context, 0, 8193);
  $headers = http_get_last_response_headers();
  demand(is_string($body) && strlen($body) <= 8192 && is_array($headers) && count($headers) >= 1 && count($headers) <= 32);
  demand(is_string($headers[0]) && preg_match('/\AHTTP\/1\.[01] 200(?: |\z)/D', $headers[0]) === 1);
  foreach ($headers as $index => $line) { demand(is_string($line) && strlen($line) <= 4096 && ($index === 0 || !str_starts_with($line, "HTTP/"))); }
  $health = decode($body);
  demand(json_encode($health, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) === $body);
  exactKeys($health, ["scenario", "environment", "variant", "phpVersion", "sapi", "expectedVersion", "matchesExpectedRuntime", "affectedUpstreamVersion", "evidenceKind"]);
  demand($health->scenario === "php2shell-container-lab" && $health->environment === "dev" && $health->variant === $annotation);
  demand($health->sapi === "apache2handler" && $health->phpVersion === $expected->images->$variant->version && $health->expectedVersion === $health->phpVersion);
  demand($health->matchesExpectedRuntime === true && $health->affectedUpstreamVersion === ($variant === "affected"));
  demand($health->evidenceKind === "observed-runtime-version-not-proof-of-compromise");
  demand(time() < $expected->windowExpiresEpoch);
  $snapshot = ["observedAt" => gmdate("Y-m-d\TH:i:s\Z"), "namespaceUid" => $nsMetadata->uid,
    "deploymentUid" => $metadata->uid, "deploymentResourceVersion" => $metadata->resourceVersion,
    "podName" => $podName, "podUid" => $podMetadata->uid, "image" => $image, "imageId" => $imageId,
    "healthStatus" => 200, "health" => $health, "isolationVerified" => true];
  if ($phase === "before") { echo $podName . " " . $metadata->resourceVersion . " " . json_encode($snapshot, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES); exit(0); }
  $before = decode($argv[4]); $process = null; $transition = null;
  demand($before->namespaceUid === $snapshot["namespaceUid"] && $before->deploymentUid === $snapshot["deploymentUid"]);
  if ($expected->operation === "run") {
    demand($before->podUid === $snapshot["podUid"] && $before->image === $image);
    demand(is_string($argv[5]) && strlen($argv[5]) <= 512 && preg_match('/\Auid=10001(?:\([a-zA-Z0-9_-]{1,32}\))? gid=10001(?:\([a-zA-Z0-9_-]{1,32}\))? groups=10001(?:\([a-zA-Z0-9_-]{1,32}\))?\z/D', $argv[5]) === 1);
    $process = ["command" => "id", "stdout" => $argv[5], "exitCode" => 0, "podName" => $podName,
      "podUid" => $podMetadata->uid, "startedAt" => $argv[6], "finishedAt" => $argv[7]];
  } else { demand($argv[5] === "" && $argv[6] === "" && $argv[7] === ""); }
  if (in_array($expected->operation, ["fix", "reset"], true)) { $transition = ["fromImage" => $before->image, "toImage" => $image]; }
  else { demand($before->podUid === $snapshot["podUid"] && $before->image === $image); }
  $record = ["schema" => "php2proof-private-live/v1", "evidenceKind" => "observed-private-administrative-action-not-exploitation",
    "operation" => $expected->operation, "operationId" => $expected->operationId, "runId" => $expected->runId,
    "windowId" => $expected->windowId, "target" => $expected->target, "startedAt" => $argv[3],
    "finishedAt" => gmdate("Y-m-d\TH:i:s\Z"), "exitCode" => 0, "before" => $before, "after" => $snapshot,
    "process" => $process, "transition" => $transition];
  $encoded = json_encode($record, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
  demand(strlen($encoded) <= 32700);
  echo "PHP2PROOF_PRIVATE_RESULT " . $encoded . "\n";
} catch (Throwable $error) { fwrite(STDERR, "Bounded private runtime observation failed; no success is asserted.\n"); exit(1); }
`;

export function privateRunCommand(target, request, now) {
  const checked = validatePrivateTarget(target, now);
  requestFor(checked, request, now);
  const transition = ["fix", "reset"].includes(request.operation);
  const limit = transition ? PRIVATE_LIVE_LIMITS.transitionSeconds : PRIVATE_LIVE_LIMITS.readSeconds;
  if (timestamp(checked.window.expiresAt, "Window expiry") - now < (limit + 5) * 1000) fail("Insufficient approved live-window time remains for this bounded operation.");
  const affected = layout(checked, "affected");
  const fixed = layout(checked, "fixed");
  const targetRecord = {
    resourceGroupId: checked.resourceGroupId, clusterId: checked.clusterId, registryId: checked.registryId,
    namespace: CONTAINER_NAMESPACE, deployment: affected.metadata.name, container: "php",
    selector: `app=${CONTAINER_SCENARIO}`,
  };
  const afterVariant = request.operation === "fix" ? "fixed" : request.operation === "reset" ? "affected" : request.variant;
  const expected = {
    operation: request.operation, operationId: request.operationId, runId: request.runId,
    windowId: checked.window.id, target: targetRecord,
    windowStartedEpoch: Math.ceil(timestamp(checked.window.notBefore, "Window start") / 1000),
    windowExpiresEpoch: Math.floor(timestamp(checked.window.expiresAt, "Window expiry") / 1000),
    beforeVariant: request.operation === "fix" ? "either" : request.operation === "reset" ? "fixed" : request.variant,
    afterVariant,
    images: Object.fromEntries([["affected", affected], ["fixed", fixed]].map(([variant, deployment]) => [variant, {
      ...checked.images[variant], image: deployment.spec.template.spec.containers[0].image,
    }])),
    baseline: affected.spec.template.spec,
  };
  const kubectl = "kubectl --request-timeout=10s";
  const scoped = `${kubectl} -n ${CONTAINER_NAMESPACE}`;
  const lines = [
    "set -eu",
    `check_window() { current=$(date -u +%s); [ "$current" -ge ${expected.windowStartedEpoch} ] && [ "$current" -lt ${expected.windowExpiresEpoch} ]; }`,
    "check_window",
    "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "before_json=''; identity=''; probe_started_at=''; probe_finished_at=''",
    "inspect() {",
    `  namespace=$(${kubectl} get namespace/${CONTAINER_NAMESPACE} -o json) || return 1`,
    `  policy=$(${scoped} get networkpolicy/deny-all -o json) || return 1`,
    `  services=$(${scoped} get services -o json) || return 1`,
    `  deployment=$(${scoped} get deployment/php-runtime -o json) || return 1`,
    `  pods=$(${scoped} get pods -l app=${CONTAINER_SCENARIO} -o json) || return 1`,
    `  replicasets=$(${scoped} get replicasets -l app=${CONTAINER_SCENARIO} -o json) || return 1`,
    `  printf '[%s,%s,%s,%s,%s,%s]' "$namespace" "$policy" "$services" "$deployment" "$pods" "$replicasets" |`,
    `    ${scoped} exec -i deployment/php-runtime -c php -- php -r ${quote(INSPECT_PHP)} -- ${quote(JSON.stringify(expected))} "$1" "$started_at" "$before_json" "$identity" "$probe_started_at" "$probe_finished_at"`,
    "}",
    "before_record=$(inspect before)",
    'pod=${before_record%% *}; remainder=${before_record#* }',
    'resource_version=${remainder%% *}; before_json=${remainder#* }',
    '[ "$pod" != "$before_record" ] && [ "$resource_version" != "$remainder" ] && [ -n "$before_json" ]',
    "check_window",
  ];
  if (request.operation === "run") {
    lines.push(
      "probe_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      `identity=$(${scoped} exec "pod/$pod" -c php -- id)`,
      "probe_finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    );
  }
  if (transition) {
    const destination = afterVariant === "fixed" ? fixed : affected;
    const patch = {
      spec: { template: { metadata: { annotations: { "dojo.variant": destination.spec.template.metadata.annotations["dojo.variant"] } },
        spec: { containers: [{ name: "php", image: destination.spec.template.spec.containers[0].image }] } } },
    };
    const tail = `"},${JSON.stringify(patch).slice(1)}`;
    lines.push(
      `patch=$(printf '%s%s%s' '{"metadata":{"resourceVersion":"' "$resource_version" ${quote(tail)})`,
      `${scoped} patch deployment/php-runtime --type=strategic --patch "$patch" > /dev/null`,
      `kubectl --request-timeout=310s -n ${CONTAINER_NAMESPACE} rollout status deployment/php-runtime --timeout=300s > /dev/null`,
    );
  }
  lines.push("check_window", "inspect after");
  const inner = lines.join("\n");
  const command = [
    "set -eu",
    `command -v kubectl date timeout > /dev/null`,
    "current=$(date -u +%s)",
    `remaining=$(( ${expected.windowExpiresEpoch} - current - 5 ))`,
    `[ "$current" -ge ${expected.windowStartedEpoch} ] && [ "$remaining" -ge ${limit} ]`,
    `timeout -s TERM -k 5 ${limit} sh -c ${quote(inner)}`,
  ].join("\n");
  if (Buffer.byteLength(command, "utf8") > PRIVATE_LIVE_LIMITS.commandBytes) fail("The closed private command exceeded its size bound.");
  return command;
}

function snapshot(value, target, label) {
  fields(value, SNAPSHOT_FIELDS, label);
  timestamp(value.observedAt, `${label} time`);
  for (const key of ["namespaceUid", "deploymentUid", "podUid"]) uuid(value[key], `${label} ${key}`);
  if (typeof value.deploymentResourceVersion !== "string" || !matches(/^[1-9][0-9]{0,19}$/, value.deploymentResourceVersion)
      || typeof value.podName !== "string" || !matches(POD_NAME, value.podName)) fail(`${label} has invalid actual Kubernetes identity metadata.`);
  const variant = ["affected", "fixed"].find((candidate) => value.image === layout(target, candidate).spec.template.spec.containers[0].image);
  if (!variant) fail(`${label} does not contain an observed reviewed derived private image.`);
  const digest = target.images[variant].digest;
  if (![value.image, `docker-pullable://${value.image}`, `containerd://${digest}`, digest].includes(value.imageId)
      || value.healthStatus !== 200 || value.isolationVerified !== true) fail(`${label} runtime image, HTTP status or isolation is unverified.`);
  fields(value.health, HEALTH_FIELDS, `${label} health`);
  const health = value.health;
  if (health.scenario !== CONTAINER_SCENARIO || health.environment !== "dev"
      || health.variant !== (variant === "affected" ? "vulnerable" : "fixed")
      || health.phpVersion !== target.images[variant].version || health.expectedVersion !== health.phpVersion
      || health.sapi !== "apache2handler" || health.matchesExpectedRuntime !== true
      || health.affectedUpstreamVersion !== (variant === "affected")
      || health.evidenceKind !== "observed-runtime-version-not-proof-of-compromise") fail(`${label} is not an actual matching Apache serving-runtime observation.`);
  return variant;
}

function commandResult(response, target) {
  const required = ["provisioningState", "exitCode", "startedAt", "finishedAt", "logs"];
  let body;
  if (response && Object.hasOwn(response, "properties")) {
    fields(response, ["id", "properties"], "ARM command result", ["name", "type"]);
    fields(response.properties, required, "ARM command result properties", ["reason"]);
    if (Object.hasOwn(response, "type") && response.type !== "Microsoft.ContainerService/managedClusters/commandResults") fail("Unexpected ARM command-result resource type.");
    body = response.properties;
  } else {
    fields(response, ["id", ...required], "CLI command result", ["reason"]);
    body = response;
  }
  if (typeof response.id !== "string" || response.id.length > 512) fail("The actual AKS command-result ID is required.");
  const prefix = `${target.clusterId}/commandResults/`;
  const commandId = response.id.toLowerCase().startsWith(prefix.toLowerCase()) ? response.id.slice(prefix.length) : response.id;
  const isUuid = matches(UUID, commandId) && commandId !== "00000000-0000-0000-0000-000000000000";
  if (!matches(/^[a-f0-9]{32}$/, commandId) && !isUuid) fail("Actual AKS command-result ID must be 32 lowercase hex characters or a non-nil UUID.");
  if (Object.hasOwn(response, "name") && response.name !== commandId) fail("Ambiguous ARM command-result identity.");
  if (body.provisioningState !== "Succeeded" || body.exitCode !== 0
      || (Object.hasOwn(body, "reason") && body.reason !== null && body.reason !== "")) fail("The actual AKS command did not complete successfully with exit code zero.");
  cloudTimestamp(body.startedAt, "AKS command start");
  cloudTimestamp(body.finishedAt, "AKS command finish");
  if (typeof body.logs !== "string" || Buffer.byteLength(body.logs, "utf8") > PRIVATE_LIVE_LIMITS.resultBytes) fail("AKS command logs are missing or oversized.");
  return { id: response.id, body };
}

export function parsePrivateRunResult(response, target, request, now) {
  const checked = validatePrivateTarget(target, now);
  requestFor(checked, request, now);
  const { id, body } = commandResult(response, checked);
  const lines = body.logs.endsWith("\n") ? body.logs.slice(0, -1).split("\n") : body.logs.split("\n");
  if (lines.length !== 1 || !lines[0].startsWith(MARKER)) fail("Exactly one bounded private JSON result record, without additional output, is required.");
  const text = lines[0].slice(MARKER.length);
  let record;
  let canonical;
  try { record = JSON.parse(text); canonical = JSON.stringify(record); }
  catch { fail("The private result record is malformed or excessively nested JSON."); }
  if (canonical !== text) fail("The private result record is noncanonical or ambiguous JSON.");
  fields(record, [
    "schema", "evidenceKind", "operation", "operationId", "runId", "windowId", "target",
    "startedAt", "finishedAt", "exitCode", "before", "after", "process", "transition",
  ], "Private result");
  if (record.schema !== SCHEMA || record.evidenceKind !== EVIDENCE_KIND
      || record.operation !== request.operation || record.operationId !== request.operationId
      || record.runId !== request.runId || record.windowId !== checked.window.id || record.exitCode !== 0) fail("The private result does not match this exact operation, run and live window.");
  fields(record.target, ["resourceGroupId", "clusterId", "registryId", "namespace", "deployment", "container", "selector"], "Observed private target");
  for (const key of ["resourceGroupId", "clusterId", "registryId"]) {
    if (record.target[key] !== checked[key]) fail("The result belongs to another private target.");
  }
  if (record.target.namespace !== CONTAINER_NAMESPACE || record.target.deployment !== "php-runtime"
      || record.target.container !== "php" || record.target.selector !== `app=${CONTAINER_SCENARIO}`) fail("The result exceeded the fixed private workload boundary.");
  const start = timestamp(record.startedAt, "Observed action start");
  const finish = timestamp(record.finishedAt, "Observed action finish");
  const cloudStart = cloudTimestamp(body.startedAt, "AKS command start");
  const cloudFinish = cloudTimestamp(body.finishedAt, "AKS command finish");
  const expires = timestamp(checked.window.expiresAt, "Live window expiry");
  const windowStart = timestamp(checked.window.notBefore, "Live window start");
  const nanoseconds = (milliseconds) => BigInt(milliseconds) * 1_000_000n;
  const limit = ["fix", "reset"].includes(request.operation) ? PRIVATE_LIVE_LIMITS.transitionSeconds : PRIVATE_LIVE_LIMITS.readSeconds;
  if (start < windowStart || finish < start
      || finish >= expires || finish > now || finish - start > limit * 1000
      || cloudStart < nanoseconds(windowStart) || cloudStart >= nanoseconds(start + 1000)
      || cloudFinish < nanoseconds(finish) || cloudFinish < cloudStart
      || cloudFinish >= nanoseconds(expires) || cloudFinish > nanoseconds(now)) fail("The actual command/action UTC times are incomplete, inconsistent or outside the approved live window.");
  const beforeVariant = snapshot(record.before, checked, "Before snapshot");
  const afterVariant = snapshot(record.after, checked, "After snapshot");
  const beforeTime = timestamp(record.before.observedAt, "Before observation time");
  const afterTime = timestamp(record.after.observedAt, "After observation time");
  if (beforeTime < start || afterTime < beforeTime || afterTime > finish
      || record.before.namespaceUid !== record.after.namespaceUid
      || record.before.deploymentUid !== record.after.deploymentUid) fail("The command did not observe a stable exact private namespace/deployment in sequence.");
  if (["run", "verify"].includes(request.operation)) {
    const either = request.operation === "verify" && request.variant === "either";
    if (beforeVariant !== afterVariant || (!either && beforeVariant !== request.variant)
        || record.before.image !== record.after.image
        || record.before.podUid !== record.after.podUid || record.before.podName !== record.after.podName
        || record.before.imageId !== record.after.imageId || record.transition !== null) fail("The read/probe result does not match one stable expected private pod and image.");
  } else {
    if ((request.operation === "reset" && beforeVariant !== "fixed")
        || afterVariant !== (request.operation === "fix" ? "fixed" : "affected")) fail("The private image transition exceeded its exact fix/reset boundary.");
    fields(record.transition, ["fromImage", "toImage"], "Observed image transition");
    if (record.transition.fromImage !== record.before.image || record.transition.toImage !== record.after.image) fail("The recorded image transition differs from actual pod observations.");
  }
  if (request.operation === "run") {
    fields(record.process, ["command", "stdout", "exitCode", "podName", "podUid", "startedAt", "finishedAt"], "Actual administrative process");
    const process = record.process;
    const processStart = timestamp(process.startedAt, "Process start");
    const processFinish = timestamp(process.finishedAt, "Process finish");
    if (process.command !== "id" || typeof process.stdout !== "string" || process.stdout.length > 512
        || !matches(ID_OUTPUT, process.stdout) || process.exitCode !== 0
        || process.podName !== record.before.podName || process.podUid !== record.before.podUid
        || processStart < beforeTime || processFinish < processStart || processFinish > afterTime) fail("The actual bounded non-root id probe output/status/times are invalid.");
  } else if (record.process !== null) fail("Only the exact run action may contain an administrative process result.");
  return freeze({ ...record, commandResult: {
    id, provisioningState: body.provisioningState, exitCode: body.exitCode,
    startedAt: body.startedAt, finishedAt: body.finishedAt,
  } });
}
