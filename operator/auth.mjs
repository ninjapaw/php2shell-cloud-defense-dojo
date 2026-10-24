import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual, createHash } from "node:crypto";
import { promisify } from "node:util";
import { assertLive, LIMITS, OperatorError } from "./config.mjs";

const scrypt = promisify(scryptCallback);
const KDF = { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
export const token = () => randomBytes(32).toString("base64url");
export const digest = (value) => createHash("sha256").update(value).digest("hex");

export async function makeVerifier(username, password, expiry, now = Date.now()) {
  if (!/^[a-z][a-z0-9-]{2,31}$/.test(username) || typeof password !== "string" || password.length < 24 || password.length > 256) {
    throw new Error("Bootstrap requires an explicit administrator name and a generated password of 24-256 characters.");
  }
  const salt = randomBytes(32);
  const verifier = await scrypt(password, salt, 64, KDF);
  return {
    schemaVersion: 1, username, salt: salt.toString("base64"), verifier: verifier.toString("base64"),
    epoch: randomUUID(), notBefore: new Date(now).toISOString(), expiresAt: expiry,
  };
}

function base64(value, size) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error("Invalid credential verifier encoding.");
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== size || bytes.toString("base64") !== value) throw new Error("Invalid credential verifier length.");
  return bytes;
}

export function validateVerifier(secret, config, now = Date.now()) {
  assertLive(config, now);
  let value;
  try { value = JSON.parse(secret.value); }
  catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    throw new Error("Key Vault credential document is invalid JSON; its value is omitted.");
  }
  const keys = ["schemaVersion", "username", "salt", "verifier", "epoch", "notBefore", "expiresAt"];
  if (secret.properties?.enabled !== true || !(secret.properties.expiresOn instanceof Date)
      || !Number.isFinite(secret.properties.expiresOn.valueOf())
      || secret.properties.expiresOn.valueOf() > config.expiresAt || secret.properties.expiresOn.valueOf() <= now
      || (secret.properties.notBefore !== undefined && (!(secret.properties.notBefore instanceof Date)
        || !Number.isFinite(secret.properties.notBefore.valueOf()) || secret.properties.notBefore.valueOf() > now))
      || !value || Object.keys(value).length !== keys.length || Object.keys(value).some((key) => !keys.includes(key))
      || value.schemaVersion !== 1 || !/^[a-z][a-z0-9-]{2,31}$/.test(value.username)
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.epoch)
      || !Number.isFinite(Date.parse(value.notBefore)) || Date.parse(value.notBefore) > now
      || value.expiresAt !== config.expiry) {
    throw new Error("Key Vault credential is disabled, expired, malformed or outside the original lab lifetime.");
  }
  base64(value.salt, 32);
  base64(value.verifier, 64);
  return value;
}

export function keyVaultCredentials(client, config) {
  return async () => {
    const secret = await client.getSecret(config.verifierSecret);
    return validateVerifier(secret, config);
  };
}

export async function passwordMatches(credential, username, password) {
  const candidate = await scrypt(password, base64(credential.salt, 32), 64, KDF);
  const expected = base64(credential.verifier, 64);
  const userMatch = timingSafeEqual(Buffer.from(digest(username)), Buffer.from(digest(credential.username)));
  return timingSafeEqual(candidate, expected) && userMatch;
}

export class Authentication {
  constructor(config, store, credentials, now = Date.now) {
    Object.assign(this, { config, store, credentials, now });
  }

  async login(username, password) {
    assertLive(this.config, this.now());
    if (typeof username !== "string" || typeof password !== "string" || username.length > 64 || password.length > 256) {
      await this.store.audit("login-denied", { reason: "invalid-input" });
      throw new OperatorError(401, "invalid-credentials", "Invalid administrator credentials.");
    }
    return this.store.withLease("auth", async () => {
      const timestamp = this.now();
      const record = await this.store.read("control/auth");
      const history = record ? record.value.attempts : [];
      if (!Array.isArray(history) || history.some((time) => !Number.isFinite(time))) throw new Error("Invalid durable authentication counter.");
      const attempts = history.filter((time) => timestamp - time < LIMITS.authWindowMs);
      if (attempts.length >= LIMITS.authAttempts) {
        await this.store.audit("login-rate-limited", {});
        throw new OperatorError(429, "login-rate-limited", "Administrator sign-in is temporarily rate limited.");
      }
      const credential = await this.credentials();
      await this.store.write("control/auth", { attempts: [...attempts, timestamp] }, record?.etag);
      if (!await passwordMatches(credential, username, password)) {
        await this.store.audit("login-denied", { reason: "invalid-credentials" });
        throw new OperatorError(401, "invalid-credentials", "Invalid administrator credentials.");
      }
      const sessionToken = token();
      const session = {
        hash: digest(sessionToken), csrf: token(), epoch: credential.epoch,
        expiresAt: Math.min(timestamp + LIMITS.sessionMs, this.config.expiresAt),
      };
      await this.store.audit("login-succeeded", { session: session.hash });
      await this.store.write(`sessions/${session.hash}`, session);
      return { sessionToken, session };
    });
  }

  async session(sessionToken) {
    assertLive(this.config, this.now());
    if (typeof sessionToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(sessionToken)) {
      throw new OperatorError(401, "login-required", "Administrator sign-in is required.");
    }
    const record = await this.store.read(`sessions/${digest(sessionToken)}`);
    const credential = await this.credentials();
    const session = record?.value;
    if (!session || session.hash !== digest(sessionToken) || session.epoch !== credential.epoch
        || !Number.isFinite(session.expiresAt) || this.now() >= session.expiresAt
        || session.expiresAt > this.config.expiresAt || typeof session.csrf !== "string") {
      throw new OperatorError(401, "login-required", "Administrator sign-in is required.");
    }
    return session;
  }

  async logout(session) {
    const record = await this.store.read(`sessions/${session.hash}`);
    if (record) await this.store.write(`sessions/${session.hash}`, { ...record.value, expiresAt: 0 }, record.etag);
    await this.store.audit("logout", { session: session.hash });
  }
}
