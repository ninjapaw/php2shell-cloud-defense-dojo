import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import reviewedImages from "../container-lab/images.json" with { type: "json" };
import { containerNames, containerWorkload } from "../scripts/lib/container-lab.mjs";
import {
  PRIVATE_LIVE_LIMITS, parsePrivateRunResult, privateRunCommand, privateTransitionConfirmation, validatePrivateTarget,
} from "../scripts/lib/private-live.mjs";

const subscription = "11111111-2222-4333-8444-555555555555";
const windowId = "22222222-3333-4444-8555-666666666666";
const operationId = "33333333-4444-4555-8666-777777777777";
const runId = "44444444-5555-4666-8777-888888888888";
const commandId = "55555555-6666-4777-8888-999999999999";
const opaqueCommandId = "0123456789abcdef0123456789abcdef";
const namespaceUid = "66666666-7777-4888-8999-aaaaaaaaaaaa";
const deploymentUid = "77777777-8888-4999-8aaa-bbbbbbbbbbbb";
const podUid = "88888888-9999-4aaa-8bbb-cccccccccccc";
const nextPodUid = "99999999-aaaa-4bbb-8ccc-dddddddddddd";
const replicaSetUid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const marker = "PHP2PROOF_PRIVATE_RESULT ";
const now = Date.parse("2026-10-25T00:20:00.000Z");
const beforeTime = "2026-10-25T00:10:01Z";
const afterTime = "2026-10-25T00:10:04Z";
const podName = "php-runtime-79d574947b-zv9ng";
const nextPodName = "php-runtime-69d574947b-xv9ng";

function target() {
  const suffix = "live1234";
  const names = containerNames({ suffix });
  const resourceGroupId = `/subscriptions/${subscription}/resourceGroups/${names.group}`;
  return {
    subscription, suffix, resourceGroupId,
    clusterId: `${resourceGroupId}/providers/Microsoft.ContainerService/managedClusters/${names.cluster}`,
    registryId: `${resourceGroupId}/providers/Microsoft.ContainerRegistry/registries/${names.registry}`,
    window: { schemaVersion: 1, id: windowId, notBefore: "2026-10-25T00:00:00.000Z",
      expiresAt: "2026-10-25T04:00:00.000Z", resourceGroup: names.group, autoTeardown: true },
    marker: { windowId, expiresAt: "2026-10-25T04:00:00.000Z" },
    images: {
      affected: { version: "8.4.26", digest: `sha256:${"a".repeat(64)}`, observedAt: "2026-10-25T00:05:00.000Z" },
      fixed: { version: "8.4.27", digest: `sha256:${"b".repeat(64)}`, observedAt: "2026-10-25T00:05:00.000Z" },
    },
  };
}

function request(operation = "run", variant = "affected", selected = target()) {
  return { operation, operationId, runId, ...(["fix", "reset"].includes(operation)
    ? { confirmation: privateTransitionConfirmation(selected, operation, now) } : { variant }) };
}

function image(variant, selected = target()) {
  return `${containerNames(selected).registry}.azurecr.io/php2shell@${selected.images[variant].digest}`;
}

function health(variant) {
  const version = variant === "affected" ? "8.4.26" : "8.4.27";
  return {
    scenario: "php2shell-container-lab", environment: "dev", variant: variant === "affected" ? "vulnerable" : "fixed",
    phpVersion: version, sapi: "apache2handler", expectedVersion: version, matchesExpectedRuntime: true,
    affectedUpstreamVersion: variant === "affected", evidenceKind: "observed-runtime-version-not-proof-of-compromise",
  };
}

function snapshot(variant, after = false, changed = false) {
  return {
    observedAt: after ? afterTime : beforeTime, namespaceUid, deploymentUid, deploymentResourceVersion: after ? "102" : "101",
    podName: changed ? nextPodName : podName, podUid: changed ? nextPodUid : podUid,
    image: image(variant), imageId: image(variant), healthStatus: 200, health: health(variant), isolationVerified: true,
  };
}

function record(operation = "run", variant = "affected") {
  const selected = target();
  const transition = ["fix", "reset"].includes(operation);
  const beforeVariant = operation === "reset" ? "fixed" : transition ? "affected" : variant;
  const afterVariant = operation === "fix" ? "fixed" : operation === "reset" ? "affected" : variant;
  const before = snapshot(beforeVariant);
  const after = snapshot(afterVariant, true, transition);
  return {
    schema: "php2proof-private-live/v1", evidenceKind: "observed-private-administrative-action-not-exploitation",
    operation, operationId, runId, windowId,
    target: { resourceGroupId: selected.resourceGroupId, clusterId: selected.clusterId, registryId: selected.registryId,
      namespace: "php2shell-isolated", deployment: "php-runtime", container: "php", selector: "app=php2shell-container-lab" },
    startedAt: "2026-10-25T00:10:00Z", finishedAt: afterTime, exitCode: 0, before, after,
    process: operation === "run" ? { command: "id", stdout: "uid=10001 gid=10001 groups=10001", exitCode: 0,
      podName, podUid, startedAt: "2026-10-25T00:10:02Z", finishedAt: "2026-10-25T00:10:03Z" } : null,
    transition: transition ? { fromImage: before.image, toImage: after.image } : null,
  };
}

function response(value = record()) {
  return {
    id: commandId, provisioningState: "Succeeded", exitCode: 0,
    startedAt: "2026-10-25T00:10:00.100Z", finishedAt: "2026-10-25T00:10:04.500Z",
    logs: `${marker}${JSON.stringify(value)}\n`,
  };
}

function literal(text, start = 0) {
  assert.equal(text[start], "'");
  let value = "";
  for (let index = start + 1; index < text.length; index += 1) {
    if (text[index] !== "'") { value += text[index]; continue; }
    if (text.slice(index, index + 4) === "'\\''") { value += "'"; index += 3; continue; }
    return { value, end: index + 1 };
  }
  assert.fail("Unclosed generated shell literal.");
}

function inspectCommand(operation = "run", variant = "affected") {
  const selected = target();
  const command = privateRunCommand(selected, request(operation, variant, selected), now);
  const inner = literal(command, command.indexOf(" sh -c ") + " sh -c ".length).value;
  const phpStart = inner.indexOf(" -- php -r ") + " -- php -r ".length;
  const php = literal(inner, phpStart);
  const metadata = literal(inner, php.end + " -- ".length);
  return { command, inner, php: php.value, expected: JSON.parse(metadata.value) };
}

test("private target accepts only the fresh scoped four-hour envelope and freezes its copy", () => {
  const original = target();
  const checked = validatePrivateTarget(original, now);
  assert.deepEqual(checked, original);
  assert.equal(Object.isFrozen(checked.images.affected), true);
  assert.equal(Object.isFrozen(original), false);
  assert.equal(checked.window.resourceGroup, "rg-p2sc-live1234-dev");
  assert.equal(reviewedImages.vulnerable.version, "8.4.26");
  assert.equal(reviewedImages.fixed.version, "8.4.27");
  assert.throws(() => validatePrivateTarget(original), /explicit current UTC time/);
  assert.throws(() => validatePrivateTarget(original, `${now}`), /explicit current UTC time/);
});

test("foreign/public targets, resource-prefix matches, overrides and accessors are refused", () => {
  for (const mutate of [
    (value) => { value.resourceGroupId = `/subscriptions/${subscription}/resourceGroups/NP-PHPToProof-Dev-CentralUS`; },
    (value) => { value.resourceGroupId += "-foreign"; },
    (value) => { value.clusterId += "/providers/Microsoft.Web/sites/public"; },
    (value) => { value.clusterId = value.clusterId.replace("live1234", "other123"); },
    (value) => { value.registryId = value.registryId.replace(subscription, windowId); },
    (value) => { value.subscription += "\n"; },
    (value) => { value.suffix = "live1234\n"; },
    (value) => { value.suffix = "x;id"; },
    (value) => { value.namespace = "default"; },
    (value) => { value.registryHost = "foreign.azurecr.io"; },
    (value) => { value.command = "whoami"; },
    (value) => { value.url = "http://example.invalid"; },
  ]) {
    const changed = target(); mutate(changed);
    assert.throws(() => validatePrivateTarget(changed, now));
  }
  let getterCalled = false;
  const changed = target();
  Object.defineProperty(changed, "subscription", { enumerable: true, get: () => { getterCalled = true; return subscription; } });
  assert.throws(() => validatePrivateTarget(changed, now), /accessor/);
  assert.equal(getterCalled, false);
  assert.throws(() => validatePrivateTarget(Object.assign(Object.create({ foreign: true }), target()), now), /plain object/);
});

test("legacy, expired, future, extended and mismatched live-window metadata cannot authorize a target", () => {
  for (const mutate of [
    (value) => { value.window.schemaVersion = "1"; },
    (value) => { value.window.autoTeardown = false; },
    (value) => { value.window.resourceGroup = "NP-PHPToProof-Dev-CentralUS"; },
    (value) => { value.window.notBefore = "2026-10-25T01:00:00.000Z"; },
    (value) => { value.window.expiresAt = "2026-10-25T00:19:00.000Z"; },
    (value) => { value.window.expiresAt = "2026-10-25T04:00:00.001Z"; },
    (value) => { value.window.notBefore = "2026-02-30T00:00:00.000Z"; },
    (value) => { value.window.expiresAt = "2026-10-25T04:00:00+00:00"; },
    (value) => { value.window.id = "00000000-0000-0000-0000-000000000000"; },
    (value) => { value.window.startedAt = value.window.notBefore; },
    (value) => { value.marker.windowId = operationId; },
    (value) => { value.marker.expiresAt = "2026-10-24T18:45:04.967Z"; },
    (value) => { value.marker.legacyExpiry = "2026-10-24T18:45:04.967Z"; },
    (value) => { delete value.marker; },
  ]) {
    const changed = target(); mutate(changed);
    assert.throws(() => validatePrivateTarget(changed, now));
  }
  assert.throws(() => validatePrivateTarget(target(), Date.parse(target().window.expiresAt)), /newly approved/);
});

test("only fresh independently observed, distinct derived digests and exact reviewed versions are accepted", () => {
  for (const mutate of [
    (value) => { value.images.affected.version = "8.4.25"; },
    (value) => { value.images.fixed.version = "8.4.26"; },
    (value) => { value.images.fixed.digest = "latest"; },
    (value) => { value.images.fixed.digest = `sha256:${"A".repeat(64)}`; },
    (value) => { value.images.fixed.digest += "\n"; },
    (value) => { value.images.fixed.digest = `sha256:${"0".repeat(64)}`; },
    (value) => { value.images.affected.digest = reviewedImages.vulnerable.source.split("@")[1]; },
    (value) => { value.images.fixed.digest = reviewedImages.fixed.source.split("@")[1]; },
    (value) => { value.images.fixed.digest = value.images.affected.digest; },
    (value) => { value.images.affected.observedAt = "2026-10-24T23:59:59.999Z"; },
    (value) => { value.images.fixed.observedAt = "2026-10-25T00:20:00.001Z"; },
    (value) => { value.images.fixed.source = reviewedImages.fixed.source; },
    (value) => { value.images.fixed.digest = { toString: () => `sha256:${"b".repeat(64)}` }; },
    (value) => { delete value.images.affected.observedAt; },
    (value) => { value.images.public = value.images.fixed; },
  ]) {
    const changed = target(); mutate(changed);
    assert.throws(() => validatePrivateTarget(changed, now));
  }
});

test("run/verify commands are closed, namespace-pinned and loopback-only with bounded waits", () => {
  const run = inspectCommand();
  const verify = inspectCommand("verify", "fixed");
  const either = inspectCommand("verify", "either");
  assert.ok(Buffer.byteLength(run.command) < PRIVATE_LIVE_LIMITS.commandBytes);
  assert.match(run.command, /timeout -s TERM -k 5 180 sh -c/);
  assert.match(run.inner, /exec "pod\/\$pod" -c php -- id/);
  assert.doesNotMatch(verify.inner, /exec "pod\/\$pod" -c php -- id/);
  assert.doesNotMatch(either.inner, /exec "pod\/\$pod" -c php -- id/);
  assert.equal(either.expected.beforeVariant, "either");
  assert.equal(either.expected.afterVariant, "either");
  for (const generated of [run, verify, either]) {
    assert.match(generated.inner, /get namespace\/php2shell-isolated -o json/);
    assert.match(generated.inner, /get networkpolicy\/deny-all -o json/);
    assert.match(generated.inner, /get deployment\/php-runtime -o json/);
    assert.match(generated.inner, /get pods -l app=php2shell-container-lab -o json/);
    assert.match(generated.inner, /get replicasets -l app=php2shell-container-lab -o json/);
    assert.match(generated.inner, /exec -i deployment\/php-runtime -c php -- php -r/);
    assert.match(generated.php, /stream_get_contents\(STDIN, 393217\)/);
    assert.match(generated.php, /http:\/\/127\.0\.0\.1:8080\/health\.php/);
    assert.match(generated.php, /"follow_location" => 0, "max_redirects" => 0, "timeout" => 3/);
    assert.doesNotMatch(generated.inner, /patch deployment|rollout status|kubectl.+(?:apply|delete|create|run|expose)\s/);
    assert.doesNotMatch(generated.php, /\b(?:eval|system|shell_exec|passthru|proc_open|popen|exec)\s*\(/);
    assert.deepEqual(generated.expected.target, record().target);
    assert.equal(generated.expected.baseline.automountServiceAccountToken, false);
    assert.deepEqual(generated.expected.baseline.containers[0].securityContext.capabilities.drop, ["ALL"]);
  }
});

test("verify either is unavailable to process Run and cannot widen Fix or Reset", () => {
  const probe = request("run", "either");
  assert.throws(() => privateRunCommand(target(), probe, now), /variant/);
  assert.throws(() => parsePrivateRunResult(response(), target(), probe, now), /variant/);
  for (const operation of ["fix", "reset"]) {
    const mutation = { ...request(operation), variant: "either" };
    assert.throws(() => privateRunCommand(target(), mutation, now), /fields/);
    assert.throws(() => parsePrivateRunResult(response(record(operation)), target(), mutation, now), /fields/);
  }
  for (const variant of ["Either", "both", "auto", "", null]) {
    assert.throws(() => privateRunCommand(target(), request("verify", variant), now), /variant/);
  }
});

test("fix and separately confirmed reset patch only the exact image and variant with optimistic concurrency", () => {
  for (const operation of ["fix", "reset"]) {
    const generated = inspectCommand(operation);
    const destination = operation === "fix" ? "fixed" : "affected";
    const match = generated.inner.match(/patch=\$\(printf '%s%s%s' '([^']+)' "\$resource_version" '([^']+)'\)/);
    assert.ok(match);
    const patch = JSON.parse(`${match[1]}101${match[2]}`);
    assert.deepEqual(patch, {
      metadata: { resourceVersion: "101" },
      spec: { template: { metadata: { annotations: { "dojo.variant": destination === "affected" ? "vulnerable" : "fixed" } },
        spec: { containers: [{ name: "php", image: image(destination) }] } } },
    });
    assert.match(generated.inner, /patch deployment\/php-runtime --type=strategic --patch "\$patch"/);
    assert.match(generated.inner, /rollout status deployment\/php-runtime --timeout=300s/);
    assert.equal(generated.expected.beforeVariant, operation === "fix" ? "either" : "fixed");
    assert.equal(generated.expected.afterVariant, destination);
    assert.match(generated.command, /timeout -s TERM -k 5 600 sh -c/);
    assert.doesNotMatch(generated.inner, /az |pricing|roleassignment|networkpolicy.+(?:patch|apply)|rollout undo|set image.+latest/);
  }
  const selected = target();
  const reset = request("reset");
  assert.match(reset.confirmation, /^RESET PRIVATE rg-p2sc-live1234-dev TO PHP 8\.4\.26 sha256:/);
  for (const confirmation of ["yes", selected.window.id, privateTransitionConfirmation(selected, "fix", now),
    reset.confirmation.replace(windowId, operationId), reset.confirmation.replace("live1234", "foreign1"),
    reset.confirmation.replace(selected.images.affected.digest, selected.images.fixed.digest)]) {
    assert.throws(() => privateRunCommand(selected, { ...reset, confirmation }, now), /confirmation/);
  }
  assert.throws(() => privateTransitionConfirmation(selected, "repair", now), /separate/);
});

test("operation input offers no arbitrary execution, host, path, target or remediation override", () => {
  for (const extra of [
    { command: "id" }, { args: ["-a"] }, { host: "127.0.0.1" }, { path: "/health.php" },
    { url: "http://127.0.0.1:8080/health.php" }, { namespace: "default" }, { deployment: "other" },
    { image: image("affected") }, { yes: true }, { confirmation: "yes" },
  ]) assert.throws(() => privateRunCommand(target(), { ...request(), ...extra }, now), /fields/);
  for (const operation of ["exec", "remediate", "repair", "uninstall", "id", "run;id", "RUN", ""]) {
    assert.throws(() => privateRunCommand(target(), { ...request(), operation }, now), /Unknown private operation/);
  }
  for (const patch of [{ operationId: "" }, { operationId: `${operationId}\n` }, { runId: 1 }, { variant: "vulnerable" }]) {
    assert.throws(() => privateRunCommand(target(), { ...request(), ...patch }, now));
  }
  let called = false;
  const accessor = request();
  Object.defineProperty(accessor, "operation", { enumerable: true, get: () => { called = true; return "run"; } });
  assert.throws(() => privateRunCommand(target(), accessor, now), /accessor/);
  assert.equal(called, false);
  const nearExpiry = Date.parse(target().window.expiresAt) - 60_000;
  assert.throws(() => privateRunCommand(target(), request(), nearExpiry), /Insufficient/);
});

test("each complete closed command passes an actual shell syntax check without execution", (context) => {
  if (process.platform === "win32") {
    context.skip("The native Windows test path uses Node/PHP; Linux CI checks POSIX shell syntax.");
    return;
  }
  const scripts = ["run", "verify", "fix", "reset"].flatMap((operation) => {
    const generated = inspectCommand(operation);
    return [generated.command, generated.inner];
  });
  for (const script of scripts) {
    const result = spawnSync("bash", ["--noprofile", "--norc", "-n", "-c", script], {
      encoding: "utf8", timeout: 15000, env: { ...process.env, BASH_ENV: "" },
    });
    if (result.error?.code === "ENOENT") { context.skip("A native Bash syntax checker is unavailable."); return; }
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "");
  }
});

test("all four operations return immutable actual-output records, never an inferred alert", () => {
  for (const [operation, variant] of [["run", "affected"], ["run", "fixed"], ["verify", "affected"], ["verify", "fixed"], ["fix", "affected"], ["reset", "fixed"]]) {
    const actual = parsePrivateRunResult(response(record(operation, variant)), target(), request(operation, variant), now);
    assert.equal(actual.operation, operation);
    assert.equal(actual.operationId, operationId);
    assert.equal(actual.commandResult.id, commandId);
    assert.equal(actual.commandResult.exitCode, 0);
    assert.equal(Object.isFrozen(actual.after.health), true);
    assert.equal(Object.hasOwn(actual, "alerts"), false);
    assert.equal(Object.hasOwn(actual, "detection"), false);
    if (operation === "run") assert.equal(actual.process.stdout, "uid=10001 gid=10001 groups=10001");
    else assert.equal(actual.process, null);
  }
});

test("verify either accepts only one unchanged actually observed reviewed digest/runtime pair", () => {
  const discovery = request("verify", "either");
  for (const variant of ["affected", "fixed"]) {
    const valid = record("verify", variant);
    const actual = parsePrivateRunResult(response(valid), target(), discovery, now);
    assert.deepEqual(actual, parsePrivateRunResult(response(valid), target(), request("verify", variant), now));
    assert.equal(actual.process, null);
    assert.equal(actual.transition, null);
    assert.equal(actual.after.image, image(variant));
    const other = variant === "affected" ? "fixed" : "affected";
    for (const mutate of [
      (value) => { value.after = snapshot(other, true); },
      (value) => { value.after.image = image(other); },
      (value) => { value.after.health = health(other); },
      (value) => { value.after.image = image(variant).replace("p2sclive1234", "foreign"); },
      (value) => { value.after.imageId = `sha256:${"c".repeat(64)}`; },
      (value) => { value.after.health.variant = "either"; },
      (value) => { value.after.health.matchesExpectedRuntime = false; },
      (value) => { value.before.isolationVerified = false; },
      (value) => { value.after.isolationVerified = false; },
      (value) => { value.after.podUid = nextPodUid; },
      (value) => { value.after.podName = nextPodName; },
      (value) => { value.process = record().process; },
      (value) => { value.transition = { fromImage: value.before.image, toImage: value.after.image }; },
    ]) {
      const changed = structuredClone(valid); mutate(changed);
      assert.throws(() => parsePrivateRunResult(response(changed), target(), discovery, now));
    }
  }
});

test("ARM and CLI result shapes are explicit, scoped and cannot be mixed or silently cast", () => {
  const flat = response();
  const { id, ...properties } = flat;
  const armId = `${target().clusterId}/commandResults/${id}`;
  const arm = { id: armId, name: id, type: "Microsoft.ContainerService/managedClusters/commandResults", properties };
  assert.equal(parsePrivateRunResult(arm, target(), request(), now).commandResult.id, armId);
  assert.equal(parsePrivateRunResult({ ...flat, reason: null }, target(), request(), now).exitCode, 0);
  const nativeUtc = { ...flat, startedAt: "2026-10-25T00:10:00.1001234+00:00", finishedAt: "2026-10-25T00:10:04.5001234+00:00" };
  assert.equal(parsePrivateRunResult(nativeUtc, target(), request(), now).commandResult.finishedAt, nativeUtc.finishedAt);
  for (const mutate of [
    (value) => { value.exitCode = 1; },
    (value) => { value.exitCode = "0"; },
    (value) => { value.provisioningState = "Running"; },
    (value) => { value.reason = "failed"; },
    (value) => { value.id = `${armId}-foreign`; },
    (value) => { value.id = armId.replace("live1234", "foreign1"); },
    (value) => { value.id = ""; },
    (value) => { value.id += "\n"; },
    (value) => { delete value.finishedAt; },
    (value) => { value.logs = {}; },
    (value) => { value.properties = properties; },
    (value) => { value.arbitrary = true; },
  ]) {
    const changed = response(); mutate(changed);
    assert.throws(() => parsePrivateRunResult(changed, target(), request(), now));
  }
  assert.throws(() => parsePrivateRunResult({ ...arm, name: runId }, target(), request(), now), /identity/);
  assert.throws(() => parsePrivateRunResult({ ...arm, type: "Microsoft.Web/sites" }, target(), request(), now), /type/);
});

test("32-hex provider command-result IDs are preserved in ARM and CLI results", () => {
  for (const token of [opaqueCommandId, "00000000000000000000000000000001"]) {
    for (const id of [token, `${target().clusterId}/commandResults/${token}`,
      `${target().clusterId.toUpperCase()}/commandResults/${token}`]) {
      const flat = { ...response(), id };
      assert.equal(parsePrivateRunResult(flat, target(), request(), now).commandResult.id, id);
      const { id: resourceId, ...properties } = flat;
      const arm = { id: resourceId, properties };
      assert.equal(parsePrivateRunResult(arm, target(), request(), now).commandResult.id, id);
      assert.equal(parsePrivateRunResult({ ...arm, name: token,
        type: "Microsoft.ContainerService/managedClusters/commandResults" }, target(), request(), now).commandResult.id, id);
    }
  }
});

test("32-hex provider ID support rejects foreign paths, malformed tokens and oversized IDs", () => {
  const prefix = `${target().clusterId}/commandResults/`;
  const invalidTokens = [
    opaqueCommandId.toUpperCase(), opaqueCommandId.slice(1), `${opaqueCommandId}0`,
    `g${opaqueCommandId.slice(1)}`, `${opaqueCommandId}_`, `${opaqueCommandId}-`,
    `${opaqueCommandId}\n`, `${opaqueCommandId}/`, `${opaqueCommandId}/child`,
    `${opaqueCommandId}?api-version=2025-08-01`, `${opaqueCommandId}#fragment`,
    ` ${opaqueCommandId}`, `${opaqueCommandId}%2fchild`, "a".repeat(513),
    "00000000-0000-0000-0000-000000000000",
  ];
  const foreignIds = [
    `${prefix.replace(subscription, windowId)}${opaqueCommandId}`,
    `${prefix.replace("rg-p2sc-live1234-dev", "rg-p2sc-foreign1-dev")}${opaqueCommandId}`,
    `${prefix.replace("p2sc-live1234-aks", "p2sc-foreign1-aks")}${opaqueCommandId}`,
    `${target().clusterId}-foreign/commandResults/${opaqueCommandId}`,
    `${target().clusterId}/commandResults%2f${opaqueCommandId}`,
    `${target().clusterId}/commandResults/../commandResults/${opaqueCommandId}`,
    `/commandResults/${opaqueCommandId}`,
  ];
  for (const id of [...invalidTokens.flatMap((token) => [token, `${prefix}${token}`]), ...foreignIds]) {
    const flat = { ...response(), id };
    assert.throws(() => parsePrivateRunResult(flat, target(), request(), now));
    const { id: resourceId, ...properties } = flat;
    assert.throws(() => parsePrivateRunResult({ id: resourceId, properties }, target(), request(), now));
  }
  const { id, ...properties } = response();
  assert.throws(() => parsePrivateRunResult({ id: opaqueCommandId, name: id, properties }, target(), request(), now), /identity/);
});

test("32-hex provider IDs do not relax operation/run UUID requirements", () => {
  for (const operation of ["run", "verify", "fix", "reset"]) {
    for (const key of ["operationId", "runId"]) {
      const changed = { ...request(operation), [key]: opaqueCommandId };
      assert.throws(() => privateRunCommand(target(), changed, now), /UUID/);
      assert.throws(() => parsePrivateRunResult(response(record(operation)), target(), changed, now), /UUID/);
    }
  }
});

test("missing, multiple, malformed, noncanonical, duplicate-key and oversized log records fail explicitly", () => {
  const valid = response().logs;
  for (const logs of [
    "", "\n", `${valid}${valid}`, `warning\n${valid}`, `${valid}\n`, `${marker}{`,
    `${marker}null`, `${marker}[]`, `${marker} ${JSON.stringify(record())}`,
    `${marker}${JSON.stringify(record()).replace('{"schema":', '{"schema":"duplicate","schema":')}`,
    `${marker}${"x".repeat(PRIVATE_LIVE_LIMITS.resultBytes)}`,
    `${marker}${"猫".repeat(PRIVATE_LIVE_LIMITS.resultBytes / 2)}`,
  ]) assert.throws(() => parsePrivateRunResult({ ...response(), logs }, target(), request(), now));
  assert.equal(parsePrivateRunResult({ ...response(), logs: valid.slice(0, -1) }, target(), request(), now).exitCode, 0);
});

test("result IDs, fixed target metadata, runtime/digests, completeness and exact types are mandatory", () => {
  for (const mutate of [
    (value) => { value.operationId = runId; },
    (value) => { value.runId = operationId; },
    (value) => { value.windowId = commandId; },
    (value) => { value.operation = "verify"; },
    (value) => { value.exitCode = 1; },
    (value) => { value.exitCode = "0"; },
    (value) => { value.evidenceKind = "synthetic"; },
    (value) => { value.target.namespace = "default"; },
    (value) => { value.target.deployment = "php-runtime-other"; },
    (value) => { value.target.container = "other"; },
    (value) => { value.target.selector = "app=*"; },
    (value) => { value.target.clusterId += "-foreign"; },
    (value) => { value.target.url = "http://example.invalid"; },
    (value) => { value.after.image = image("affected").replace("p2sclive1234", "foreign"); },
    (value) => { value.after.imageId = `sha256:${"c".repeat(64)}`; },
    (value) => { value.after.healthStatus = "200"; },
    (value) => { value.after.isolationVerified = "true"; },
    (value) => { value.after.health.phpVersion = "8.4.27"; },
    (value) => { value.after.health.expectedVersion = "8.4.27"; },
    (value) => { value.after.health.sapi = "cli"; },
    (value) => { value.after.health.matchesExpectedRuntime = "true"; },
    (value) => { value.after.health.affectedUpstreamVersion = false; },
    (value) => { value.after.health.extra = "unexpected"; },
    (value) => { value.after.podUid = "not-a-uuid"; },
    (value) => { value.after.podName += "\n"; },
    (value) => { value.after.deploymentResourceVersion += "\n"; },
    (value) => { value.after.namespaceUid = nextPodUid; },
    (value) => { value.after.deploymentUid = nextPodUid; },
    (value) => { value.after.podUid = nextPodUid; },
    (value) => { delete value.after.image; },
    (value) => { value.after.defaulted = true; },
    (value) => { value.transition = {}; },
  ]) {
    const changed = record(); mutate(changed);
    assert.throws(() => parsePrivateRunResult(response(changed), target(), request(), now));
  }
});

test("actual id evidence cannot contain another command, root identity, extra groups, output or status", () => {
  for (const patch of [
    { command: "whoami" }, { command: "id; whoami" }, { stdout: "uid=0 gid=0 groups=0" },
    { stdout: "uid=10001 gid=10001 groups=10001,0(root)" }, { stdout: "uid=10001 gid=10001 groups=10001\n" },
    { stdout: "uid=10001 gid=10001 groups=10001; id" }, { stdout: "" }, { stdout: ["uid=10001"] },
    { stdout: "x".repeat(513) }, { exitCode: "0" }, { exitCode: 1 },
    { podUid: nextPodUid }, { podName: nextPodName }, { arbitrary: true },
    { startedAt: "2026-10-25T00:10:00Z" }, { finishedAt: "2026-10-25T00:10:05Z" },
  ]) {
    const changed = record(); Object.assign(changed.process, patch);
    assert.throws(() => parsePrivateRunResult(response(changed), target(), request(), now));
  }
  const named = record();
  named.process.stdout = "uid=10001(lab) gid=10001(lab) groups=10001(lab)";
  assert.equal(parsePrivateRunResult(response(named), target(), request(), now).process.stdout, named.process.stdout);
  const verify = record("verify");
  verify.process = record().process;
  assert.throws(() => parsePrivateRunResult(response(verify), target(), request("verify"), now), /Only the exact run/);
});

test("fix cannot downgrade, reset requires a fixed predecessor, and transition records must match actual images", () => {
  for (const operation of ["fix", "reset"]) {
    const changed = record(operation);
    changed.transition.toImage = image(operation === "fix" ? "affected" : "fixed");
    assert.throws(() => parsePrivateRunResult(response(changed), target(), request(operation), now), /transition differs/);
  }
  const reset = record("reset");
  reset.before = snapshot("affected");
  reset.transition.fromImage = reset.before.image;
  assert.throws(() => parsePrivateRunResult(response(reset), target(), request("reset"), now), /fix\/reset boundary/);
  const fix = record("fix");
  fix.after = snapshot("affected", true);
  fix.transition.toImage = fix.after.image;
  assert.throws(() => parsePrivateRunResult(response(fix), target(), request("fix"), now), /fix\/reset boundary/);
  const alreadyFixed = record("fix");
  alreadyFixed.before = snapshot("fixed");
  alreadyFixed.transition.fromImage = alreadyFixed.before.image;
  assert.equal(parsePrivateRunResult(response(alreadyFixed), target(), request("fix"), now).after.health.phpVersion, "8.4.27");
});

test("actual UTC command, observation and process chronology must fit the current window without defaults", () => {
  for (const mutate of [
    (value) => { value.startedAt = "2026-10-24T23:59:59Z"; },
    (value) => { value.finishedAt = "2026-10-25T00:21:00Z"; },
    (value) => { value.finishedAt = "2026-10-25T04:00:00Z"; },
    (value) => { value.finishedAt = "2026-10-25T00:09:59Z"; },
    (value) => { value.startedAt = "2026-10-25T00:10:00+00:00"; },
    (value) => { value.before.observedAt = "2026-10-25T00:09:59Z"; },
    (value) => { value.after.observedAt = "2026-10-25T00:10:05Z"; },
    (value) => { value.process.finishedAt = "2026-10-25T00:10:01Z"; },
    (value) => { delete value.process.startedAt; },
  ]) {
    const changed = record(); mutate(changed);
    assert.throws(() => parsePrivateRunResult(response(changed), target(), request(), now));
  }
  for (const patch of [
    { startedAt: "2026-10-25T00:10:02.000Z" }, { finishedAt: "2026-10-25T00:10:03.999Z" },
    { finishedAt: "2026-10-25T00:21:00.000Z" }, { finishedAt: null },
    { startedAt: "2026-10-25T00:10:00+01:00" }, { finishedAt: "2026-10-25T00:10:04.12345678Z" },
    { startedAt: "2026-10-25T00:10:00.100Z\n" },
  ]) assert.throws(() => parsePrivateRunResult({ ...response(), ...patch }, target(), request(), now));
});

function kubernetesFixture(variant, after = false, changed = false) {
  const manifest = containerWorkload("p2sclive1234.azurecr.io", target().images[variant].digest, variant === "affected" ? "vulnerable" : "fixed");
  const namespace = manifest.items[0];
  namespace.metadata.uid = namespaceUid;
  const deployment = manifest.items[3];
  Object.assign(deployment.metadata, { uid: deploymentUid, generation: 1, resourceVersion: after ? "102" : "101" });
  deployment.status = { observedGeneration: 1, replicas: 1, readyReplicas: 1, availableReplicas: 1, updatedReplicas: 1 };
  const name = changed ? nextPodName : podName;
  const replicaSetName = name.slice(0, name.lastIndexOf("-"));
  const pod = {
    metadata: { name, uid: changed ? nextPodUid : podUid, namespace: "php2shell-isolated",
      labels: deployment.spec.template.metadata.labels, annotations: deployment.spec.template.metadata.annotations,
      ownerReferences: [{ apiVersion: "apps/v1", kind: "ReplicaSet", name: replicaSetName, uid: replicaSetUid, controller: true }] },
    spec: structuredClone(deployment.spec.template.spec),
    status: { phase: "Running", containerStatuses: [{ name: "php", ready: true, image: image(variant), imageID: image(variant), state: { running: {} } }] },
  };
  return {
    namespace, policy: manifest.items[1], services: { items: [] }, deployment, pods: { items: [pod] },
    replicasets: { items: [{ metadata: { name: replicaSetName, uid: replicaSetUid,
      ownerReferences: [{ apiVersion: "apps/v1", kind: "Deployment", name: "php-runtime", uid: deploymentUid, controller: true }] } }] },
    health: health(variant), podName: name,
  };
}

function inspectPhp(generated, fixture, phase, before = "") {
  const observed = phase === "before" ? beforeTime : afterTime;
  const headers = Object.hasOwn(fixture, "headers") ? fixture.headers : ["HTTP/1.1 200 OK"];
  const body = Object.hasOwn(fixture, "body") ? fixture.body : JSON.stringify(fixture.health);
  const fixturePrefix = `
namespace PrivateLiveFixture;
use \\stdClass; use \\RuntimeException; use \\Throwable;
function time() { return ${Date.parse(observed) / 1000}; }
function gmdate($format) { return \\gmdate($format, time()); }
function gethostname() { return ${JSON.stringify(fixture.podName)}; }
function http_get_last_response_headers() { return json_decode(${JSON.stringify(JSON.stringify(headers))}, true, 64, JSON_THROW_ON_ERROR); }
function file_get_contents($url, $includePath, $context, $offset, $length) {
  if ($url !== "http://127.0.0.1:8080/health.php" || $includePath !== false || $offset !== 0 || $length !== 8193) { throw new RuntimeException("Unreviewed HTTP request."); }
  $options = stream_context_get_options($context)["http"];
  if ($options["method"] !== "GET" || $options["follow_location"] !== 0 || $options["max_redirects"] !== 0 || $options["timeout"] !== 3) { throw new RuntimeException("Unreviewed HTTP options."); }
  return ${JSON.stringify(body)};
}
`;
  return spawnSync("php", ["-r", fixturePrefix + generated.php, "--", JSON.stringify(generated.expected), phase,
    "2026-10-25T00:10:00Z", before, phase === "after" && generated.expected.operation === "run" ? "uid=10001 gid=10001 groups=10001" : "",
    phase === "after" && generated.expected.operation === "run" ? "2026-10-25T00:10:02Z" : "",
    phase === "after" && generated.expected.operation === "run" ? "2026-10-25T00:10:03Z" : ""],
  { input: JSON.stringify(["namespace", "policy", "services", "deployment", "pods", "replicasets"].map((key) => fixture[key])),
    encoding: "utf8", timeout: 5000, maxBuffer: PRIVATE_LIVE_LIMITS.resultBytes });
}

test("the exact generated PHP inspector compiles and emits parseable real-shape observations using local-only fixtures", (context) => {
  const generated = inspectCommand();
  const syntax = spawnSync("php", ["-l"], { input: `<?php\n${generated.php}`, encoding: "utf8", timeout: 5000 });
  if (syntax.error?.code === "ENOENT") { context.skip("PHP CLI is unavailable; no external resources are used."); return; }
  assert.equal(syntax.error, undefined);
  assert.equal(syntax.status, 0, syntax.stderr);
  for (const operation of ["run", "verify", "fix", "reset"]) {
    const command = inspectCommand(operation);
    const beforeVariant = operation === "reset" ? "fixed" : "affected";
    const afterVariant = operation === "fix" ? "fixed" : "affected";
    const before = inspectPhp(command, kubernetesFixture(beforeVariant), "before");
    assert.equal(before.error, undefined);
    assert.equal(before.status, 0, before.stderr);
    const snapshotText = before.stdout.split(" ").slice(2).join(" ");
    assert.deepEqual(JSON.parse(snapshotText), snapshot(beforeVariant));
    const after = inspectPhp(command, kubernetesFixture(afterVariant, true, ["fix", "reset"].includes(operation)), "after", snapshotText);
    assert.equal(after.error, undefined);
    assert.equal(after.status, 0, after.stderr);
    const parsed = parsePrivateRunResult({ ...response(), logs: after.stdout }, target(), request(operation), now);
    assert.equal(parsed.operation, operation);
    assert.equal(parsed.after.image, image(afterVariant));
  }
});

test("verify either independently inspects both reviewed variants and refuses live pair or isolation changes", (context) => {
  const generated = inspectCommand("verify", "either");
  for (const variant of ["affected", "fixed"]) {
    const before = inspectPhp(generated, kubernetesFixture(variant), "before");
    if (before.error?.code === "ENOENT") { context.skip("PHP CLI is unavailable; no external resources are used."); return; }
    assert.equal(before.error, undefined);
    assert.equal(before.status, 0, before.stderr);
    const snapshotText = before.stdout.split(" ").slice(2).join(" ");
    assert.deepEqual(JSON.parse(snapshotText), snapshot(variant));
    const after = inspectPhp(generated, kubernetesFixture(variant, true), "after", snapshotText);
    assert.equal(after.error, undefined);
    assert.equal(after.status, 0, after.stderr);
    const actual = parsePrivateRunResult({ ...response(), logs: after.stdout }, target(), request("verify", "either"), now);
    assert.equal(actual.before.image, image(variant));
    assert.equal(actual.after.image, image(variant));
    assert.equal(actual.after.health.phpVersion, target().images[variant].version);
    assert.equal(actual.process, null);
    assert.equal(actual.transition, null);
    const other = variant === "affected" ? "fixed" : "affected";
    const changedVariant = kubernetesFixture(other, true);
    const drift = kubernetesFixture(variant, true);
    drift.policy.spec.egress = [{}];
    const mismatchedPair = kubernetesFixture(variant, true);
    mismatchedPair.health = health(other);
    for (const changed of [changedVariant, drift, mismatchedPair]) {
      const rejected = inspectPhp(generated, changed, "after", snapshotText);
      assert.equal(rejected.error, undefined);
      assert.equal(rejected.status, 1, rejected.stderr);
      assert.equal(rejected.stdout, "");
      assert.match(rejected.stderr, /no success is asserted/);
    }
  }
});

test("the generated inspector refuses drift before probing or changing the reviewed deployment", (context) => {
  const generated = inspectCommand();
  for (const mutate of [
    (value) => { value.namespace.metadata.labels["pod-security.kubernetes.io/enforce"] = "privileged"; },
    (value) => { value.policy.spec.egress = [{}]; },
    (value) => { value.services.items.push({ metadata: { name: "public" } }); },
    (value) => { value.deployment.spec.replicas = 2; },
    (value) => { value.deployment.spec.template.spec.containers[0].command = ["id"]; },
    (value) => { value.pods.items.push(structuredClone(value.pods.items[0])); },
    (value) => { value.pods.items[0].spec.automountServiceAccountToken = true; },
    (value) => { value.pods.items[0].spec.hostNetwork = true; },
    (value) => { value.pods.items[0].spec.shareProcessNamespace = true; },
    (value) => { value.pods.items[0].spec.securityContext.supplementalGroups = [0]; },
    (value) => { value.pods.items[0].spec.securityContext.sysctls = [{ name: "kernel.example", value: "1" }]; },
    (value) => { value.pods.items[0].spec.containers[0].securityContext.runAsUser = 0; },
    (value) => { value.pods.items[0].spec.containers[0].securityContext.appArmorProfile = { type: "Unconfined" }; },
    (value) => { value.pods.items[0].spec.containers[0].securityContext.capabilities.add = ["NET_ADMIN"]; },
    (value) => { value.pods.items[0].spec.volumes.push({ name: "host", hostPath: { path: "/" } }); },
    (value) => { value.pods.items[0].status.containerStatuses[0].ready = false; },
    (value) => { value.pods.items[0].status.containerStatuses[0].imageID = `sha256:${"c".repeat(64)}`; },
    (value) => { value.replicasets.items[0].metadata.ownerReferences[0].uid = nextPodUid; },
    (value) => { value.health.phpVersion = "8.4.27"; },
    (value) => { value.health.matchesExpectedRuntime = "true"; },
    (value) => { value.health.unexpected = "value"; },
    (value) => { delete value.health.expectedVersion; },
    (value) => { value.headers = ["HTTP/1.1 503 Service Unavailable"]; },
    (value) => { value.headers = ["HTTP/1.1 302 Found"]; },
    (value) => { value.headers = ["HTTP/1.1 200 OK", "HTTP/1.1 302 Found"]; },
    (value) => { value.headers = null; },
    (value) => { value.body = "x".repeat(8193); },
    (value) => { value.body = "{"; },
    (value) => { value.body = JSON.stringify(value.health).replace('{"scenario":', '{"scenario":"duplicate","scenario":'); },
    (value) => { value.namespace.metadata.annotations = { oversized: "x".repeat(393217) }; },
  ]) {
    const changed = kubernetesFixture("affected"); mutate(changed);
    const result = inspectPhp(generated, changed, "before");
    if (result.error?.code === "ENOENT") { context.skip("PHP CLI is unavailable; no external resources are used."); return; }
    assert.equal(result.error, undefined);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /no success is asserted/);
  }
  const reset = inspectPhp(inspectCommand("reset"), kubernetesFixture("affected"), "before");
  assert.equal(reset.status, 1, reset.stderr);
});

test("import performs no process or network action", () => {
  const source = `
import childProcess from "node:child_process";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import dgram from "node:dgram";
import { syncBuiltinESMExports } from "node:module";
const denied = () => { throw new Error("Import attempted process/network activity."); };
for (const key of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) childProcess[key] = denied;
for (const module of [http, https]) { module.request = denied; module.get = denied; }
net.connect = denied; net.createConnection = denied; tls.connect = denied; dgram.createSocket = denied;
globalThis.fetch = denied; syncBuiltinESMExports();
await import(${JSON.stringify(new URL("../scripts/lib/private-live.mjs", import.meta.url).href)});
console.log("import-only");
`;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", source], { encoding: "utf8", timeout: 5000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "import-only");
});
