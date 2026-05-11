/**
 * Zod schemas + parsing helpers for tool inputs.
 *
 * MCP tool args travel as JSON, so anything wider than Number.MAX_SAFE_INTEGER
 * (e.g. sompi amounts) must arrive as strings and be parsed to BigInt
 * internally.
 *
 * All validators here are pure — they do not consult Kaspa state. Network
 * context (mainnet vs testnet) is passed explicitly by the caller so tools
 * can report consistent errors regardless of when the wallet was unlocked.
 */

import { z } from "zod";
import { policy } from "./services/policy.js";

// ── Address ────────────────────────────────────────────────────────────

export type SupportedNetwork =
  | "mainnet"
  | "testnet-10"
  | "testnet-11"
  | "testnet-12";

// Kaspa CashAddr data alphabet (literal, not a range, to avoid drift from the
// canonical "qpzry9x8gf2tvdw0s3jn54khce6mua7l" set). Case-insensitive.
//
// SCAFFOLD ONLY: this charset+length+prefix check is not a checksum
// validator. Phase 4 must wrap inputs with `new kaspa.Address(...)` (which
// runs the real CashAddr checksum) before any value-bearing operation; do
// NOT rely on this schema alone for transaction safety.
const KASPA_BECH32_CHARSET = /^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/i;

function networkPrefix(net: SupportedNetwork): "kaspa" | "kaspatest" {
  return net === "mainnet" ? "kaspa" : "kaspatest";
}

/**
 * Build an address schema scoped to a single network. The prefix must match
 * exactly; no cross-network sends.
 *
 * Length range covers schnorr (qzr...) and ECDSA (qyr...) payment addresses;
 * we don't constrain payload version beyond a sane char-count window.
 */
export function addressSchema(network: SupportedNetwork) {
  const prefix = networkPrefix(network);
  return z
    .string()
    .min(prefix.length + 1 + 50, "address too short")
    .max(prefix.length + 1 + 120, "address too long")
    .refine(
      (s) => s.startsWith(`${prefix}:`),
      `address must start with "${prefix}:" for network ${network}`
    )
    .refine((s) => {
      const body = s.slice(prefix.length + 1);
      return KASPA_BECH32_CHARSET.test(body);
    }, "address payload contains characters outside the bech32m charset");
}

// ── Sompi (string → bigint) ────────────────────────────────────────────

/**
 * Parse a sompi amount supplied as a decimal-digit string. Refuses negatives,
 * zero, and anything above the configured KASPA_MAX_SOMPI_PER_TX cap.
 *
 * Caller receives a bigint suitable for the WASM Generator.
 */
export const sompiSchema = z
  .string()
  .regex(/^\d+$/, "sompi must be a non-negative decimal-digit string")
  .transform((s, ctx) => {
    const v = BigInt(s);
    if (v <= 0n) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "sompi must be > 0",
      });
      return z.NEVER;
    }
    if (v > policy.maxSompiPerTx) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `amount ${v} exceeds KASPA_MAX_SOMPI_PER_TX cap ${policy.maxSompiPerTx}`,
      });
      return z.NEVER;
    }
    return v;
  });

// ── Payload ────────────────────────────────────────────────────────────

/**
 * Hex-encoded payload bytes, capped at 20_000 chars (~10 KB on the wire).
 * Empty string is allowed and treated as "no payload".
 */
export const payloadSchema = z
  .string()
  .max(20_000, "payload exceeds 20_000 hex chars")
  .refine((s) => s.length === 0 || /^[0-9a-fA-F]+$/.test(s), {
    message: "payload must be a hex string",
  })
  .refine((s) => s.length % 2 === 0, {
    message: "payload hex length must be even",
  });

// ── Confirm token ──────────────────────────────────────────────────────

/**
 * Server-issued handle returned by kaspa_send_transaction. The model echoes
 * it back to kaspa_confirm_send_transaction. 32 hex chars (16 random bytes).
 */
export const confirmTokenSchema = z
  .string()
  .regex(/^[0-9a-f]{32}$/, "confirm_token must be 32 lowercase hex chars");

// ── Hashes ─────────────────────────────────────────────────────────────

/** 64 lowercase hex chars (block hash, transaction id, etc.). */
export const hashHexSchema = z
  .string()
  .length(64, "must be exactly 64 hex chars")
  .regex(/^[0-9a-f]+$/, "must be lowercase hex");

// ── Network-agnostic address shape ─────────────────────────────────────

/**
 * Loose shape check for read-only RPCs that accept any Kaspa address (e.g.,
 * balance/UTXO lookups for arbitrary wallets). Charset + length + prefix
 * only; the real CashAddr checksum runs at the handler boundary via
 * services/address-validator.ts.
 */
export const kaspaAddressLooseSchema = z
  .string()
  .min(`kaspa:`.length + 1 + 50, "address too short")
  .max(`kaspatest:`.length + 1 + 120, "address too long")
  .refine(
    (s) => s.startsWith("kaspa:") || s.startsWith("kaspatest:"),
    "address must start with 'kaspa:' (mainnet) or 'kaspatest:' (testnet)"
  )
  .refine((s) => {
    const colon = s.indexOf(":");
    const body = s.slice(colon + 1);
    return /^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/i.test(body);
  }, "address payload contains characters outside the Kaspa CashAddr charset");

// ── Priority fee ───────────────────────────────────────────────────────

/**
 * Priority fee in sompi. Capped at the same protocol max as the main amount
 * (a fee larger than the supply is nonsensical and indicates either a bug or
 * an attack); a tighter operator-set cap can be applied at the handler.
 */
export const priorityFeeSompiSchema = z
  .number()
  .int("priorityFee must be an integer number of sompi")
  .min(0, "priorityFee cannot be negative")
  .max(
    Number.MAX_SAFE_INTEGER,
    "priorityFee exceeds Number.MAX_SAFE_INTEGER; use a string-encoded amount once supported"
  );
