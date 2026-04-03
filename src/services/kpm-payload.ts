/**
 * Parse KPM anchor payloads from Kaspa transactions.
 *
 * KPM payload format (from KPM spec v4.0.3):
 *   Bytes: "KPM1" (4 bytes) || modeByte (1 byte) || hash (32 bytes)
 *   Total: 37 bytes
 *
 *   modeByte = 0x01 → INDIVIDUAL (event hash)
 *   modeByte = 0x02 → MERKLE (merkle root)
 *
 * The payload is stored in the transaction's `payload` field as hex.
 */

import type { KpmAnchorPayload } from "../types.js";

const KPM_MAGIC = "4b504d31"; // "KPM1" in hex
const KPM_PAYLOAD_HEX_LENGTH = 74; // 37 bytes * 2

const MODE_MAP: Record<string, string> = {
  "01": "INDIVIDUAL",
  "02": "MERKLE",
};

export function parseKpmPayload(payloadHex: string): KpmAnchorPayload {
  if (!payloadHex || payloadHex.length < KPM_PAYLOAD_HEX_LENGTH) {
    return { raw: payloadHex, isKpmPayload: false };
  }

  const magic = payloadHex.substring(0, 8);
  if (magic !== KPM_MAGIC) {
    return { raw: payloadHex, isKpmPayload: false };
  }

  const modeByte = payloadHex.substring(8, 10);
  const anchorMode = MODE_MAP[modeByte];
  if (!anchorMode) {
    return { raw: payloadHex, isKpmPayload: false };
  }

  const hash = payloadHex.substring(10, 74);

  return {
    raw: payloadHex,
    isKpmPayload: true,
    anchorMode,
    hash,
  };
}

/**
 * Check if a transaction's subnetwork indicates it carries data
 * (non-native subnetwork or has a non-empty payload).
 */
export function hasPayload(subnetworkId: string, payload: string): boolean {
  return payload !== "" && payload !== "00";
}
