/**
 * Pending-transaction state for the two-step send flow.
 *
 * The map is a MODULE singleton — every importer of this file shares the
 * same Map instance. This is load-bearing for HTTP mode: index.ts builds
 * a fresh McpServer per /mcp request, so per-McpServer state would not
 * survive the boundary between kaspa_send_transaction (request 1) and
 * kaspa_confirm_send_transaction (request 2). Module-singleton storage
 * is the property that makes the two-step flow work across requests.
 *
 * Lifecycle:
 *   - createPending(...) → token + digest + expiresAt
 *   - consumePending(token) → entry on success (and DELETES); null if
 *     missing/expired. Single-use by construction; no tombstones.
 *   - Periodic sweeper expires entries even if no caller wakes them up.
 *
 * The TxParams stored here have already been validated by buildPreview
 * (cap, recipient checksum, payload, etc.). signAndSubmit re-validates
 * the bundle anyway as a defense-in-depth check.
 */

import { createHash, randomBytes } from "node:crypto";
import { policy } from "./policy.js";
import type { TxParams } from "./transaction.js";

export class PendingCapReachedError extends Error {
  constructor(public readonly cap: number, public readonly current: number) {
    super(`pending-tx cap reached: ${current}/${cap}`);
    this.name = "PendingCapReachedError";
  }
}

export interface Pending {
  params: TxParams;
  digest: string;
  preview: string;
  feeSompi: string;
  createdAt: number;
  expiresAt: number;
}

const DEFAULT_TTL_MS = 5 * 60_000;
const SWEEP_INTERVAL_MS = 60_000;

const pending = new Map<string, Pending>();

/**
 * 8 hex chars derived from the full transaction identity PLUS the per-call
 * token. Including the token guarantees per-preview uniqueness even when
 * params + UTXO state happen to be stable, so a stale-preview approval
 * cannot trick an operator into re-confirming a tx they meant to expire.
 */
function computeDigest(params: TxParams, feeSompi: string, token: string): string {
  const material = JSON.stringify({
    n: params.network,
    t: params.to,
    a: params.amountSompi,
    f: params.priorityFeeSompi,
    p: params.payload ?? "",
    s: params.senderAddress,
    fee: feeSompi,
    tk: token,
  });
  return createHash("sha256").update(material).digest("hex").slice(0, 8);
}

export interface CreateResult {
  token: string;
  digest: string;
  expiresAt: number;
}

export function createPending(
  params: TxParams,
  feeSompi: string,
  preview: string,
  ttlMs: number = DEFAULT_TTL_MS,
): CreateResult {
  // Defense in depth: refuse to grow the map past the configured cap so
  // a model that spams preview-creation cannot OOM the process or starve
  // legitimate confirmations of map slots. Sweep expired first so a single
  // stale entry doesn't permanently block new previews.
  if (pending.size >= policy.maxPendingTx) {
    expireSweep();
    if (pending.size >= policy.maxPendingTx) {
      throw new PendingCapReachedError(policy.maxPendingTx, pending.size);
    }
  }

  // 32 lowercase hex chars (16 random bytes), per validation.ts schema.
  const token = randomBytes(16).toString("hex");
  const digest = computeDigest(params, feeSompi, token);
  const now = Date.now();
  const entry: Pending = {
    params,
    digest,
    preview,
    feeSompi,
    createdAt: now,
    expiresAt: now + ttlMs,
  };
  pending.set(token, entry);
  return { token, digest, expiresAt: entry.expiresAt };
}

/**
 * Atomic get-and-delete. Returns the entry if present AND not expired;
 * deletes the entry either way (an expired entry is consumed but yields
 * null, so a stale token cannot be retried after expiry).
 */
export function consumePending(token: string): Pending | null {
  const entry = pending.get(token);
  if (!entry) return null;
  pending.delete(token);
  if (entry.expiresAt < Date.now()) return null;
  return entry;
}

/** Sweep expired entries. Called periodically; exposed for tests. */
export function expireSweep(): number {
  const now = Date.now();
  let removed = 0;
  for (const [token, entry] of pending) {
    if (entry.expiresAt < now) {
      pending.delete(token);
      removed++;
    }
  }
  return removed;
}

const sweepTimer = setInterval(expireSweep, SWEEP_INTERVAL_MS);
// Don't pin the event loop open just for the sweeper — process should exit
// cleanly when nothing else is happening.
sweepTimer.unref();

// ── Test affordances ──────────────────────────────────────────────────

export function _resetForTests(): void {
  pending.clear();
}

export function _pendingSize(): number {
  return pending.size;
}
