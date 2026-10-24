import { names } from "../../scripts/lib/config.mjs";
import { configuration, FDID } from "../../tests/support/harness.mjs";
import { makeVerifier, Authentication } from "../auth.mjs";
import { OperatorError } from "../config.mjs";

export const PASSWORD = "unit-test-only-generated-password-not-a-live-secret";
export const NOW = Date.now();
export const expiry = new Date(NOW + 3_600_000).toISOString();
export const verifier = await makeVerifier("unit-admin", PASSWORD, expiry, NOW - 1000);

export function config() {
  const invocation = configuration("validate");
  return {
    invocation, names: names(invocation), origin: "https://operator-unit.azurefd.net",
    frontDoorId: FDID, expiry, expiresAt: Date.parse(expiry),
    verifierSecret: "operator-admin-verifier",
    workspaceId: "66666666-6666-4666-8666-666666666666",
  };
}

export class MemoryStore {
  constructor() {
    this.rows = new Map();
    this.queue = [];
    this.events = [];
    this.leases = new Set();
    this.version = 0;
  }
  async read(key) { return structuredClone(this.rows.get(key)); }
  async write(key, value, etag) {
    const previous = this.rows.get(key);
    if ((etag && previous?.etag !== etag) || (!etag && previous)) throw new Error("Storage compare-and-swap conflict.");
    this.rows.set(key, { value: structuredClone(value), etag: String(++this.version) });
  }
  async audit(event, fields) { this.events.push({ event, ...structuredClone(fields) }); }
  async withLease(name, operation) {
    if (this.leases.has(name)) throw new OperatorError(409, "busy", "Lease held.");
    this.leases.add(name);
    try { return await operation({ assertLease: () => {} }); }
    finally { this.leases.delete(name); }
  }
  async send(jobId) {
    this.queue.push({ messageText: Buffer.from(JSON.stringify({ jobId })).toString("base64"), messageId: jobId, dequeueCount: 1 });
  }
  async receive() { return this.queue[0]; }
  async complete(message) { this.queue = this.queue.filter((item) => item !== message); }
  async recentJobs() { return [...this.rows.entries()].filter(([key]) => key.startsWith("jobs/")).map(([, row]) => row.value); }
}

export async function setup() {
  const cfg = config();
  const store = new MemoryStore();
  let current = structuredClone(verifier);
  const credentials = async () => current;
  const auth = new Authentication(cfg, store, credentials, () => NOW);
  const login = await auth.login("unit-admin", PASSWORD);
  return { cfg, store, credentials, auth, ...login, rotate: () => { current = { ...current, epoch: "77777777-7777-4777-8777-777777777777" }; } };
}
