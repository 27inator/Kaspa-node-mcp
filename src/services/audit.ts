/**
 * Append-only JSONL audit log at ~/.kaspa-mcp/audit.log (chmod 600).
 *
 * Forensic baseline: we record events that matter for understanding what
 * the wallet was asked to do and what happened. Specifically we DO NOT
 * record:
 *   - Bearer tokens, confirm tokens (use sha256[:16] hash for correlation)
 *   - Mnemonics, private keys
 *   - Wallet passwords (env or TTY-typed)
 *   - Full transaction payloads (just length)
 *
 * Best-effort writes: any failure (permission denied, disk full, etc.)
 * is logged to stderr and SWALLOWED. Audit must never block a tx flow
 * or crash the server.
 */

import { appendFileSync, chmodSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

const AUDIT_DIR = join(homedir(), ".kaspa-mcp");
const AUDIT_FILE = join(AUDIT_DIR, "audit.log");

let initialized = false;
let initError: string | undefined;

function ensureDir(): void {
  if (initialized) return;
  initialized = true;
  try {
    mkdirSync(AUDIT_DIR, { mode: 0o700, recursive: true });
  } catch (e) {
    // If we couldn't even create the dir, remember why so the first
    // audit call can surface it once and then go silent.
    initError = e instanceof Error ? e.message : String(e);
  }
}

/**
 * Stable correlation hash for tokens / secrets we don't want to log raw.
 * 16 hex chars is plenty for forensic linking inside a session-bounded log.
 */
export function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex").slice(0, 16);
}

export type AuditEvent =
  | "wallet_unlocked"
  | "send_preview_created"
  | "confirm_attempted"
  | "confirm_submitted"
  | "confirm_failed"
  | "rate_limited"
  | "preview_rate_limited"
  | "pending_cap_reached";

let firstWriteFailed = false;

// Defense-in-depth field-name redactor. Caller discipline is the primary
// guardrail (callers pass tokenHash, never token; preview byte count,
// never raw payload); this central scrub catches accidental leaks of
// secret-flavored field names regardless of caller behavior. It is NOT a
// complete sanitizer — anyone wanting to hide a secret can still name the
// field something innocuous, or stuff it inside a value. The point is
// only to catch obvious regressions.
//
// Rule: lowercased key containing any sensitive fragment is redacted.
// Exception: keys ending in "hash" are exempt (tokenHash, previewHash,
// any *_hash) because by convention those carry opaque correlation
// material, not raw secrets.

// Fragments are matched as case-insensitive substrings of the lowercased
// key. They're chosen short enough to catch obvious compound names
// (walletPassword, private_key, authHeader) without depending on exact
// shape — separators (_, -, camelCase) all collapse under toLowerCase().
const SENSITIVE_FRAGMENTS = [
  "password",
  "mnemonic",
  "seed",
  "secret",
  "bearer",
  "auth",      // authorization, authHeader, authToken, …
  "private",   // privateKey, private_key, privateSeed, …
  "token",     // token, confirm_token, confirmToken, bearerToken, …
];

function shouldRedactKey(key: string): boolean {
  const lower = key.toLowerCase();
  if (lower.endsWith("hash")) return false;
  return SENSITIVE_FRAGMENTS.some((f) => lower.includes(f));
}

/**
 * Recursively scrub `fields`. Arrays and plain objects are walked; primitives
 * pass through. A guard caps recursion depth to keep an accidental cycle
 * from looping forever; a circular ref already throws inside JSON.stringify,
 * but this is defense in depth.
 */
function scrubFields(fields: Record<string, unknown>): Record<string, unknown> {
  return scrubValue(fields, 0) as Record<string, unknown>;
}

const MAX_SCRUB_DEPTH = 6;

function scrubValue(v: unknown, depth: number): unknown {
  if (depth > MAX_SCRUB_DEPTH) return "[REDACTED_DEPTH]";
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map((item) => scrubValue(item, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    if (shouldRedactKey(k)) {
      out[k] = "[REDACTED]";
    } else {
      out[k] = scrubValue(val, depth + 1);
    }
  }
  return out;
}

export function audit(
  event: AuditEvent,
  fields: Record<string, unknown> = {},
): void {
  ensureDir();
  const record = {
    ts: new Date().toISOString(),
    event,
    pid: process.pid,
    ...scrubFields(fields),
  };
  let line: string;
  try {
    line = JSON.stringify(record);
  } catch (e) {
    // Defensive: refuse to write malformed JSON. Surface why.
    console.error(
      `[kaspa-mcp] audit serialize failed for ${event}: ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
    return;
  }
  try {
    appendFileSync(AUDIT_FILE, line + "\n", { mode: 0o600 });
    chmodSync(AUDIT_FILE, 0o600);
  } catch (e) {
    // Log once per session, then go silent — repeated audit failures
    // (e.g., read-only homedir) shouldn't flood stderr.
    if (!firstWriteFailed) {
      firstWriteFailed = true;
      const reason = e instanceof Error ? e.message : String(e);
      const prefix = initError ? `init: ${initError}; write: ` : "";
      console.error(
        `[kaspa-mcp] audit write failed (logging this once): ${prefix}${reason}`,
      );
    }
  }
}

// ── Bucketed rate-limit auditing ──────────────────────────────────────
//
// rate_limited events can fire unauthenticated (HTTP layer) at whatever
// rate a local loop pushes. Writing one audit line per event would let
// any localhost process force unbounded sync disk I/O. Instead, we
// accumulate counts in memory and flush a single line per layer every
// few seconds. First event in an empty window is also delayed to the
// next flush — that's the cost of bounded I/O.

interface RateLimitedWindow {
  count: number;
  firstAt: number;
  lastAt: number;
}
const RATE_LIMITED_FLUSH_INTERVAL_MS = 5_000;
const rateLimitedAccum = new Map<string, RateLimitedWindow>();
let flushTimer: NodeJS.Timeout | undefined;

function ensureFlushTimer(): void {
  if (flushTimer) return;
  flushTimer = setInterval(flushRateLimited, RATE_LIMITED_FLUSH_INTERVAL_MS);
  flushTimer.unref();
}

function flushRateLimited(): void {
  for (const [layer, w] of rateLimitedAccum) {
    if (w.count === 0) continue;
    audit("rate_limited", {
      layer,
      count: w.count,
      firstAt: new Date(w.firstAt).toISOString(),
      lastAt: new Date(w.lastAt).toISOString(),
    });
    w.count = 0;
  }
}

/**
 * Accumulate a rate-limited event for later flush. Use this instead of
 * calling audit("rate_limited", ...) directly — it's the only audit path
 * that fires from unauthenticated request handling, so it MUST be bounded.
 */
export function auditRateLimited(layer: string): void {
  ensureFlushTimer();
  const w = rateLimitedAccum.get(layer);
  const now = Date.now();
  if (!w) {
    rateLimitedAccum.set(layer, { count: 1, firstAt: now, lastAt: now });
  } else {
    if (w.count === 0) w.firstAt = now;
    w.count++;
    w.lastAt = now;
  }
}

/** Test affordance: force a flush of pending rate-limited windows. */
export function _flushRateLimitedForTests(): void {
  flushRateLimited();
}

/**
 * Production hook: call before process exit so any accumulated rate-limit
 * windows get a final flush to disk. Without this, a server that exits
 * shortly after a denial storm would never write the audit line.
 */
export function flushPendingAudit(): void {
  flushRateLimited();
}

/** Test affordance: reset the once-per-session warning flag. */
export function _resetForTests(): void {
  firstWriteFailed = false;
  initialized = false;
  initError = undefined;
  rateLimitedAccum.clear();
}

/** Test affordance: return the audit file path so tests can read it. */
export function _getAuditFilePath(): string {
  return AUDIT_FILE;
}
