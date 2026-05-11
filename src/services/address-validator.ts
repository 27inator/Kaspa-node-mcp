/**
 * Runtime Kaspa address validation.
 *
 * The Zod schemas in validation.ts cover prefix/length/charset, but only
 * `new kaspa.Address(...)` runs the real CashAddr checksum. Every tool that
 * accepts a Kaspa address as input must call validateKaspaAddress() before
 * letting the value reach a downstream RPC or transaction builder.
 */

import * as kaspa from "kaspa-wasm";

const { Address, NetworkType } = kaspa;

export type KaspaAddressPrefix = "kaspa" | "kaspatest";

/**
 * Validate a Kaspa address by constructing a kaspa.Address (which runs
 * checksum verification) and optionally checking that the prefix matches an
 * expected network. Returns the parsed Address on success; throws an Error
 * with a stable message shape on failure (callers wrap into McpError or
 * tool-result errors as they prefer).
 */
export function validateKaspaAddress(
  addr: string,
  expectedPrefix?: KaspaAddressPrefix
): kaspa.Address {
  let parsed: kaspa.Address;
  try {
    parsed = new Address(addr);
  } catch (e) {
    throw new Error(
      `invalid Kaspa address: ${e instanceof Error ? e.message : String(e)}`
    );
  }
  if (expectedPrefix && parsed.prefix !== expectedPrefix) {
    throw new Error(
      `address prefix "${parsed.prefix}" does not match expected "${expectedPrefix}"`
    );
  }
  return parsed;
}

/**
 * Map a wallet's NetworkType to the matching CashAddr prefix.
 * Mainnet → "kaspa", everything else (testnet-*) → "kaspatest".
 */
export function prefixForNetwork(network: kaspa.NetworkType): KaspaAddressPrefix {
  return network === NetworkType.Mainnet ? "kaspa" : "kaspatest";
}
