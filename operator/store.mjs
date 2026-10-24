import { randomUUID } from "node:crypto";
import { LIMITS, OperatorError } from "./config.mjs";

const missing = (error) => error?.statusCode === 404;
const conflict = (error) => [409, 412].includes(error?.statusCode);

export class AzureStore {
  constructor(container, queue, log = console.error) {
    Object.assign(this, { container, queue, log });
  }

  blob(key) {
    if (!/^(?:control|sessions|jobs|evidence|audit|locks)\/[a-zA-Z0-9/_-]{1,160}$/.test(key) || key.includes("..")) {
      throw new Error("Invalid private operator storage key.");
    }
    return this.container.getBlockBlobClient(`${key}.json`);
  }

  async read(key) {
    const blob = this.blob(key);
    let properties;
    try { properties = await blob.getProperties(); }
    catch (error) {
      if (missing(error)) return undefined;
      throw error;
    }
    if (!Number.isInteger(properties.contentLength) || properties.contentLength < 1 || properties.contentLength > LIMITS.jsonBytes) {
      throw new Error("Private operator record exceeds its size or shape bound.");
    }
    const bytes = await blob.downloadToBuffer(0, properties.contentLength, { conditions: { ifMatch: properties.etag } });
    return { value: JSON.parse(bytes.toString("utf8")), etag: properties.etag };
  }

  async write(key, value, etag) {
    const bytes = Buffer.from(JSON.stringify(value));
    if (bytes.length > LIMITS.jsonBytes) throw new Error("Private operator record exceeds its size bound.");
    await this.blob(key).uploadData(bytes, {
      conditions: etag ? { ifMatch: etag } : { ifNoneMatch: "*" },
      blobHTTPHeaders: { blobContentType: "application/json; charset=utf-8", blobCacheControl: "no-store" },
    });
  }

  async audit(event, fields) {
    const timestamp = new Date().toISOString();
    await this.write(`audit/${timestamp.slice(0, 10)}/${randomUUID()}`, { schemaVersion: 1, timestamp, event, ...fields });
  }

  async withLease(name, operation) {
    if (!/^[a-z-]{1,32}$/.test(name)) throw new Error("Invalid operator lease name.");
    const blob = this.blob(`locks/${name}`);
    try { await blob.uploadData(Buffer.from("{}"), { conditions: { ifNoneMatch: "*" } }); }
    catch (error) { if (!conflict(error)) throw error; }
    const lease = blob.getBlobLeaseClient();
    try { await lease.acquireLease(60); }
    catch (error) {
      if (conflict(error)) throw new OperatorError(409, "busy", "An operator action is already in progress. Try again later.");
      throw error;
    }
    let lost;
    let renewing = Promise.resolve();
    const timer = setInterval(() => {
      renewing = renewing.then(async () => {
        if (lost) return;
        try { await lease.renewLease(); }
        catch (error) {
          lost = error;
          this.log("ERROR: durable operator lease renewal failed; further dispatch is denied.");
        }
      });
    }, 20_000);
    timer.unref();
    const assertLease = () => {
      if (lost) throw new Error("Durable operator lease was lost; further dispatch is denied.");
    };
    try {
      const result = await operation({ assertLease });
      assertLease();
      return result;
    } finally {
      clearInterval(timer);
      await renewing;
      try { await lease.releaseLease(); }
      catch (error) {
        this.log("ERROR: durable operator lease release failed; storage reconciliation is required.");
        throw error;
      }
    }
  }

  async send(jobId) {
    await this.queue.sendMessage(Buffer.from(JSON.stringify({ jobId })).toString("base64"));
  }

  async receive() {
    const result = await this.queue.receiveMessages({ numberOfMessages: 1, visibilityTimeout: 660 });
    if (!Array.isArray(result.receivedMessageItems)) throw new Error("Invalid durable queue response.");
    return result.receivedMessageItems[0];
  }

  async complete(message) {
    await this.queue.deleteMessage(message.messageId, message.popReceipt);
  }

  async recentJobs() {
    const entries = [];
    for await (const item of this.container.listBlobsFlat({ prefix: "jobs/" })) {
      if (entries.length >= 1000) throw new Error("Private run history exceeded its reviewed listing bound; use the storage audit for older runs.");
      if (!(item.properties.lastModified instanceof Date)) throw new Error("Missing job-history timestamp.");
      entries.push(item);
    }
    const result = [];
    for (const item of entries.sort((a, b) => b.properties.lastModified - a.properties.lastModified).slice(0, 20)) {
      const key = item.name.replace(/\.json$/, "");
      const record = await this.read(key);
      if (record) result.push(record.value);
    }
    return result.sort((a, b) => b.queuedAt.localeCompare(a.queuedAt));
  }
}
