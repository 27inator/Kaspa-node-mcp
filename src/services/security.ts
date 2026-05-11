/**
 * Transport-level security helpers used by the HTTP middleware in index.ts.
 *
 * Every check here is meant to fail closed: ambiguous input → reject.
 */

import { timingSafeEqual } from "node:crypto";

/**
 * Constant-time bearer comparison.
 *
 * Returns false if the header is missing/malformed. Returns false if lengths
 * differ (timingSafeEqual would throw); we synthesize a same-length compare
 * against the expected token so the timing side-channel does not depend on
 * which mismatch path was hit.
 */
export function timingSafeBearer(
  authHeader: string | undefined,
  expectedToken: string
): boolean {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return false;
  const presented = authHeader.slice("Bearer ".length);
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(expectedToken, "utf8");
  if (a.length !== b.length) {
    // Compare b to itself so the function still does the same amount of work.
    timingSafeEqual(b, b);
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * DNS-rebinding defense: only accept requests whose Host header points at the
 * loopback we bound to. Reject any other host (including external hostnames
 * that happen to resolve to 127.0.0.1).
 */
export function isAllowedHost(
  hostHeader: string | undefined,
  port: number
): boolean {
  if (!hostHeader) return false;
  const allowed = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  return allowed.has(hostHeader.toLowerCase());
}

/**
 * Origin allowlist. An absent Origin is permitted (non-browser callers like
 * curl/scripts don't send one); a present Origin must match exactly.
 */
export function isAllowedOrigin(
  originHeader: string | undefined,
  allowed: readonly string[]
): boolean {
  if (!originHeader) return true;
  return allowed.includes(originHeader);
}

/**
 * Best-effort redaction for error messages that might bubble up to the model
 * or transport. JS strings are immutable and we do not control every code path
 * inside kaspa-wasm, so this is defense-in-depth, not a guarantee.
 */
export function redact(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  // Mnemonic phrases are 12/15/18/21/24 lowercase words separated by spaces.
  // Match runs of >=12 such words and replace with [REDACTED MNEMONIC].
  const mnemonicLike = /\b([a-z]{3,8}(?:\s+[a-z]{3,8}){11,23})\b/g;
  return raw.replace(mnemonicLike, "[REDACTED MNEMONIC]");
}
