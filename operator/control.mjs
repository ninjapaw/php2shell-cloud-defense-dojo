import { randomUUID } from "node:crypto";
import { execute, investigationQuery } from "../scripts/dojo.mjs";
import { UUID } from "../scripts/lib/config.mjs";
import { redact, assertOwnedGroup } from "../scripts/lib/safety.mjs";
import { assertLive, LIMITS, OPERATIONS, OperatorError } from "./config.mjs";
import { captureEvidence } from "./evidence.mjs";

const JOB_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class ControlPlane {
  constructor(config, store, credentials, azureFactory, { run = execute, fetchImpl = fetch, now = Date.now, log = console.error } = {}) {
    Object.assign(this, { config, store, credentials, azureFactory, run, fetchImpl, now, log });
  }

  async authorize(session) {
    assertLive(this.config, this.now());
    const stored = await this.store.read(`sessions/${session.hash}`);
    const credential = await this.credentials();
    if (!stored || stored.value.hash !== session.hash || !Number.isFinite(stored.value.expiresAt)
        || stored.value.epoch !== credential.epoch || stored.value.epoch !== session.epoch
        || (this.config.liveWindow && credential.epoch !== this.config.liveWindow.id)
        || stored.value.expiresAt <= this.now() || stored.value.expiresAt > this.config.expiresAt) {
      throw new OperatorError(401, "session-expired", "Administrator authorization expired or was revoked.");
    }
  }

  async start(session, operation, idempotencyKey, sourceJobId, huntId, responseInput, liveInput) {
    await this.authorize(session);
    if (!OPERATIONS.includes(operation) || !JOB_ID.test(idempotencyKey)) {
      await this.store.audit("dispatch-denied", { session: session.hash, reason: "outside-catalogue" });
      throw new OperatorError(400, "not-allowed", "Only the fixed harmless/read-only catalogue is executable.");
    }
    if (operation === "hunt-pack") (await import("./hunts.mjs")).assertHuntId(huntId);
    else if (huntId !== undefined) throw new OperatorError(400, "unexpected-hunt", "Only the hunting catalogue accepts a hunt identifier.");
    if (operation !== "response" && responseInput !== undefined) throw new OperatorError(400, "unexpected-response", "Only the response catalogue accepts a response approval.");
    if (operation !== "live" && liveInput !== undefined) throw new OperatorError(400, "unexpected-live", "Only the private live playbook accepts a live approval.");
    if (operation !== "live" && this.config.liveWindow && this.now() >= this.config.originalExpiresAt) {
      throw new OperatorError(410, "original-expired", "The original public-lab execution authorization remains expired. Use only the separately scoped private playbook.");
    }
    return this.store.withLease("dispatch", async () => {
      if (operation === "collect-evidence") {
        if (!JOB_ID.test(sourceJobId)) throw new OperatorError(400, "source-run-required", "Select an existing actual simulator run.");
        const source = await this.store.read(`jobs/${sourceJobId}`);
        if (!source || source.value.target !== this.config.names.appId || source.value.operation !== "simulate"
            || !UUID.test(source.value.result?.runId)) throw new OperatorError(400, "source-run-required", "An actual persisted simulator result is required.");
      } else if (sourceJobId !== undefined) {
        throw new OperatorError(400, "unexpected-source", "This operation does not accept an external run or target.");
      }
      const existing = await this.store.read(`jobs/${idempotencyKey}`);
      if (existing) {
        if (existing.value.sessionHash !== session.hash || existing.value.operation !== operation || existing.value.sourceJobId !== sourceJobId
            || existing.value.huntId !== huntId || JSON.stringify(existing.value.response) !== JSON.stringify(responseInput)
            || JSON.stringify(existing.value.live) !== JSON.stringify(liveInput)) {
          throw new OperatorError(409, "idempotency-conflict", "This request identifier already belongs to another action.");
        }
        return existing.value;
      }
      const approvedResponse = operation === "response"
        ? await (await import("./response.mjs")).validateResponseDispatch(this, session, responseInput) : undefined;
      const approvedLive = operation === "live"
        ? await (await import("./live-control.mjs")).validateLiveDispatch(this, session, liveInput) : undefined;
      const current = await this.store.read("control/dispatch");
      const timestamp = this.now();
      const history = current ? current.value.starts : [];
      if (!Array.isArray(history) || history.some((time) => !Number.isFinite(time))) throw new Error("Invalid durable dispatch counter.");
      let preserveUnresolved = false;
      if (current?.value.activeJob) {
        const active = await this.store.read(`jobs/${current.value.activeJob}`);
        if (!active || ["queued", "running", "reconciliation-required"].includes(active.value.status)) {
          const scopedReconciliation = operation === "live" && active?.value.status === "reconciliation-required"
            && active.value.target === this.config.liveWindow.groupId && active.value.liveWindowId === this.config.liveWindow.id
            && ["plan", "verify", "collect", "reconcile"].includes(approvedLive.id);
          if (!scopedReconciliation) throw new OperatorError(409, "busy", "An active or unresolved run already owns this lab.");
          preserveUnresolved = approvedLive.id !== "reconcile";
        }
      }
      const starts = history.filter((time) => timestamp - time < 3_600_000);
      if (starts.length >= (operation === "live" ? LIMITS.liveStartsPerHour : LIMITS.startsPerHour)
          || starts.some((time) => timestamp - time < LIMITS.startIntervalMs)) {
        await this.store.audit("dispatch-rate-limited", { session: session.hash });
        throw new OperatorError(429, "rate-limited", "Lab execution rate limit reached.");
      }
      const job = {
        schemaVersion: 1, id: idempotencyKey, operation, status: "queued",
        sessionHash: session.hash, credentialEpoch: session.epoch,
        queuedAt: new Date(timestamp).toISOString(), expiresAt: this.config.expiry,
        target: operation === "live" ? this.config.liveWindow.groupId : this.config.names.appId,
        ...(sourceJobId ? { sourceJobId } : {}),
        ...(huntId ? { huntId } : {}),
        ...(approvedResponse ? { response: approvedResponse } : {}),
        ...(approvedLive ? { live: approvedLive, liveWindowId: this.config.liveWindow.id } : {}),
      };
      await this.store.audit("dispatch-intent", { jobId: job.id, operation, session: session.hash });
      await this.store.write(`jobs/${job.id}`, job);
      await this.store.write("control/dispatch", { starts: [...starts, timestamp],
        activeJob: preserveUnresolved ? current.value.activeJob : job.id }, current?.etag);
      try { await this.store.send(job.id); }
      catch (error) {
        const saved = await this.store.read(`jobs/${job.id}`);
        await this.store.write(`jobs/${job.id}`, { ...job, status: "enqueue-failed", error: "Durable queue dispatch failed; no execution is asserted." }, saved.etag);
        await this.store.audit("dispatch-failed", { jobId: job.id });
        throw error;
      }
      return job;
    });
  }

  async workOnce() {
    return this.store.withLease("worker", async ({ assertLease }) => {
      const message = await this.store.receive(this.config.liveWindow ? 780 : 660);
      if (!message) return false;
      let parsed;
      try { parsed = JSON.parse(Buffer.from(message.messageText, "base64").toString("utf8")); }
      catch {
        await this.store.audit("queue-rejected", { reason: "invalid-message" });
        await this.store.complete(message);
        throw new Error("Invalid durable queue message was rejected without dispatch.");
      }
      if (!parsed || Object.keys(parsed).length !== 1 || !JOB_ID.test(parsed.jobId)) {
        await this.store.audit("queue-rejected", { reason: "invalid-job-id" });
        await this.store.complete(message);
        throw new Error("Queue message escaped the fixed job-ID protocol.");
      }
      const saved = await this.store.read(`jobs/${parsed.jobId}`);
      if (!saved) throw new Error("Queued job has no durable audit/state record; execution denied.");
      const job = saved.value;
      if (job.status !== "queued" || !Number.isInteger(message.dequeueCount) || message.dequeueCount !== 1) {
        if (["queued", "running"].includes(job.status)) {
          await this.store.write(`jobs/${job.id}`, {
            ...job, status: "reconciliation-required",
            error: "Delivery or execution may already have started. Automatic replay is forbidden.",
          }, saved.etag);
          await this.store.audit("replay-denied", { jobId: job.id });
        }
        await this.store.complete(message);
        return false;
      }
      const expectedTarget = job.operation === "live" ? this.config.liveWindow?.groupId : this.config.names.appId;
      if (!OPERATIONS.includes(job.operation) || job.target !== expectedTarget || job.expiresAt !== this.config.expiry
          || (job.operation === "live" && job.liveWindowId !== this.config.liveWindow?.id)
          || (job.operation !== "live" && this.config.liveWindow && this.now() >= this.config.originalExpiresAt)) {
        await this.store.audit("execution-boundary-denied", { jobId: job.id });
        await this.store.write(`jobs/${job.id}`, { ...job, status: "failed",
          error: "Durable job does not match the immutable operation, target and authorization window; no execution occurred." }, saved.etag);
        await this.store.complete(message);
        return false;
      }
      const session = { hash: job.sessionHash, epoch: job.credentialEpoch };
      const deadline = Math.min(this.now() + (job.operation === "live" ? LIMITS.liveJobMs : LIMITS.jobMs), this.config.expiresAt);
      const guard = async () => {
        assertLease();
        if (this.now() >= deadline) throw new Error("The bounded job deadline has ended; no further request is permitted.");
        await this.authorize(session);
        if (this.now() >= deadline) throw new Error("The bounded job deadline has ended; no further request is permitted.");
      };
      let running;
      let result;
      let evidence;
      try {
        await guard();
        running = { ...job, status: "running", startedAt: new Date(this.now()).toISOString() };
        await this.store.audit("execution-starting", { jobId: job.id, operation: job.operation });
        await this.store.write(`jobs/${job.id}`, running, saved.etag);
        const azure = this.azureFactory(guard);
        let requestCount = 0;
        const guardedFetch = async (url, options) => {
          await guard();
          requestCount += 1;
          if (requestCount > 20) throw new Error("The fixed lab HTTP request budget was exceeded.");
          const parsed = new URL(url);
          await this.store.audit("http-intent", {
            jobId: job.id, index: requestCount, host: parsed.hostname, path: parsed.pathname,
            runId: parsed.searchParams.get("runId"),
          });
          await guard();
          const response = await this.fetchImpl(url, {
            ...options, signal: AbortSignal.any([options.signal, AbortSignal.timeout(Math.max(1, deadline - this.now()))]),
          });
          await this.store.audit("http-observed", { jobId: job.id, index: requestCount, status: response.status });
          return response;
        };
        if (job.operation === "live") {
          ({ result, evidence } = await (await import("./live.mjs")).runLiveJob(this, job, azure, guard, guardedFetch));
          if (evidence) await this.store.write(`evidence/${job.id}`, evidence);
        } else if (job.operation === "response") {
          result = await (await import("./response.mjs")).runResponseJob(this, job, azure, guard, guardedFetch);
        } else if (job.operation === "hunt-pack") {
          assertOwnedGroup(await azure.az(["group", "show", "--name", this.config.names.group]), this.config.invocation);
          result = await (await import("./hunts.mjs")).runHunts(this.config, azure, job.huntId,
            { guard, log: this.log, now: this.now });
          for (const item of result.results) {
            const key = `evidence/hunting/${item.id}`;
            const previous = await this.store.read(key);
            await this.store.write(key, item, previous?.etag);
          }
        } else if (job.operation === "collect-evidence") {
          assertOwnedGroup(await azure.az(["group", "show", "--name", this.config.names.group]), this.config.invocation);
          const source = JOB_ID.test(job.sourceJobId) ? await this.store.read(`jobs/${job.sourceJobId}`) : undefined;
          if (!source || source.value.target !== this.config.names.appId || source.value.operation !== "simulate"
              || !UUID.test(source.value.result?.runId)) throw new Error("Evidence refresh lost its original guarded simulator result.");
          result = source.value.result;
        } else {
          result = await this.run({ ...this.config.invocation, command: job.operation === "investigate" ? "validate" : job.operation, yes: true }, {
            az: azure.az, fetchImpl: guardedFetch,
            log: (messageText) => this.log(`operator job ${job.id}: ${redact(messageText)}`),
          });
          if (job.operation === "investigate") result = {
            validation: result,
            assessments: (await azure.graph(investigationQuery(this.config.invocation))).data,
            note: "Actual matching posture only; the full optional hunting guide remains in the operator CLI documentation.",
          };
        }
        if (["simulate", "collect-evidence"].includes(job.operation)) {
          if (!UUID.test(result?.runId)) throw new Error("Simulator returned no real run identity.");
          evidence = await captureEvidence(this.config, result, azure, this.log);
          await this.store.write(`evidence/${job.id}`, evidence);
        }
        await guard();
        const latest = await this.store.read(`jobs/${job.id}`);
        const completeEvidence = (!evidence || Object.values(evidence.captures).every((source) => source.status === "queried"))
          && (job.operation !== "hunt-pack" || result.results.every((item) => item.status === "queried"))
          && (job.operation !== "live" || !evidence || Object.values(evidence.plans).every((plan) => plan.status === "queried"))
          && (job.operation !== "response" || (!result.sourceGaps?.length
            && (result.kind !== "response-verification" || result.resolved === true)));
        const ingested = !evidence || job.operation === "live" || (evidence.captures.application.status === "queried"
          && new Set(evidence.captures.application.rows.map((row) => row.Signal)).size === 5);
        const finished = {
          ...running, status: completeEvidence && ingested ? "completed" : "completed-with-evidence-gaps",
          finishedAt: new Date(this.now()).toISOString(),
          result, ...(evidence ? { evidenceKey: `evidence/${job.id}`, runId: result.runId } : {}),
        };
        await this.store.audit("execution-completed", { jobId: job.id, operation: job.operation });
        await this.store.write(`jobs/${job.id}`, finished, latest.etag);
      } catch (error) {
        const uncertain = error.mutationMayHaveOccurred || result?.kind === "response-change" || result?.kind === "private-live-change";
        const latest = await this.store.read(`jobs/${job.id}`);
        await this.store.audit("execution-failed", { jobId: job.id, reason: redact(error.message) });
        await this.store.write(`jobs/${job.id}`, {
          ...latest.value, status: uncertain ? "reconciliation-required" : "failed", finishedAt: new Date(this.now()).toISOString(),
          error: redact(error.message),
          ...(uncertain ? { automaticReplayForbidden: true } : {}),
        }, latest.etag);
        this.log(`ERROR: operator job ${job.id} failed: ${redact(error.message)}`);
      }
      await this.store.complete(message);
      return true;
    });
  }
}

export const newRequestId = () => randomUUID();
