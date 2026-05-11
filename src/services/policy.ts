/**
 * Single source of truth for security-relevant env flags.
 *
 * Parsed and validated once at startup. Bad config fails fast before
 * `server.connect()` so misconfiguration cannot silently weaken the
 * server's posture.
 *
 * Caller contract: import `policy` (the frozen object), never read
 * process.env for any of these values elsewhere.
 */

const KAS_PROTOCOL_MAX_SOMPI: bigint = 2_870_000_000n * 100_000_000n; // ~2.87e18, supply ceiling

function parseFlag(name: string): boolean {
  const v = process.env[name];
  return v === "1" || v === "true";
}

function parseAllowedOrigins(raw: string | undefined): readonly string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function parseMaxSompi(raw: string | undefined): bigint {
  // Default: 1000 KAS = 100_000_000_000 sompi. Conservative cap that requires
  // explicit override for larger sends.
  if (!raw) return 100_000_000_000n;
  if (!/^\d+$/.test(raw)) {
    throw new Error(
      `KASPA_MAX_SOMPI_PER_TX must be a non-negative integer, got "${raw}"`
    );
  }
  const v = BigInt(raw);
  if (v <= 0n) {
    throw new Error(`KASPA_MAX_SOMPI_PER_TX must be > 0, got ${v}`);
  }
  if (v > KAS_PROTOCOL_MAX_SOMPI) {
    throw new Error(
      `KASPA_MAX_SOMPI_PER_TX ${v} exceeds protocol max ${KAS_PROTOCOL_MAX_SOMPI}`
    );
  }
  return v;
}

function validateBearerToken(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  // Restrict to printable ASCII the safe-URL/base64url/hex sets cover, so
  // `raw.length` (JS code units) and `Buffer.byteLength(raw, "utf8")` agree.
  // This keeps the constant-time bearer compare predictable.
  if (!/^[A-Za-z0-9_\-+/=]+$/.test(raw)) {
    throw new Error(
      "KASPA_MCP_TOKEN must contain only printable ASCII " +
        "(hex / base64 / base64url chars: A-Z a-z 0-9 _-+/=)"
    );
  }
  if (raw.length < 32) {
    throw new Error(
      `KASPA_MCP_TOKEN must be at least 32 chars (got ${raw.length}). ` +
        `Generate one with: openssl rand -hex 32`
    );
  }
  return raw;
}

export interface Policy {
  readonly enableHttp: boolean;
  readonly enableSigning: boolean;
  readonly enableWalletSetup: boolean;
  readonly bearerToken: string | undefined;
  readonly allowedOrigins: readonly string[];
  readonly walletPasswordEnv: string | undefined;
  readonly maxSompiPerTx: bigint;
  readonly httpPort: number;
  // ── Rate limit knobs ────────────────────────────────────────────────
  // HTTP bucket is process-global (loopback-only server; per-IP isn't
  // meaningful). Defaults aim above a normal MCP client's
  // initialize/list/call burst, below anything that would feel like a
  // legitimate attack.
  readonly httpRateCapacity: number;       // burst budget
  readonly httpRateRefillPerSec: number;   // steady-state rate
  // Signing bucket gates confirm tokens consumption. Tighter limits — a
  // human can't realistically approve more than a few txs per minute.
  readonly signingRateCapacity: number;
  readonly signingRateRefillPerSec: number;
  // Preview bucket gates kaspa_send_transaction so a model in stdio mode
  // (no HTTP rate limit) cannot spam preview-creation, which would burn
  // RPC work AND fill the pending-tx map.
  readonly previewRateCapacity: number;
  readonly previewRateRefillPerSec: number;
  // Hard cap on simultaneous pending-confirmation entries. Defense in
  // depth: even if a preview bucket is set high, the map cannot grow
  // unboundedly.
  readonly maxPendingTx: number;
}

function buildPolicy(): Policy {
  const enableHttp = parseFlag("KASPA_ENABLE_HTTP");
  const bearerToken = validateBearerToken(process.env.KASPA_MCP_TOKEN);

  // HTTP transport is fail-closed: bearer token is mandatory when enabled.
  if (enableHttp && !bearerToken) {
    throw new Error(
      "KASPA_ENABLE_HTTP=1 requires KASPA_MCP_TOKEN to be set " +
        "(>=32 chars). Generate one with: openssl rand -hex 32"
    );
  }

  const portRaw = process.env.PORT ?? "3000";
  // parseInt is too permissive ("3000abc" → 3000). Require all-digits then
  // coerce, so trailing junk fails closed instead of silently truncating.
  if (!/^\d+$/.test(portRaw)) {
    throw new Error(`PORT must be a decimal integer, got "${portRaw}"`);
  }
  const port = Number(portRaw);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    throw new Error(`PORT must be 1-65535, got "${portRaw}"`);
  }

  const policy: Policy = {
    enableHttp,
    enableSigning: parseFlag("KASPA_ENABLE_SIGNING"),
    enableWalletSetup: parseFlag("KASPA_ENABLE_WALLET_SETUP"),
    bearerToken,
    allowedOrigins: parseAllowedOrigins(process.env.KASPA_ALLOWED_ORIGINS),
    walletPasswordEnv: process.env.KASPA_WALLET_PASSWORD,
    maxSompiPerTx: parseMaxSompi(process.env.KASPA_MAX_SOMPI_PER_TX),
    httpPort: port,
    httpRateCapacity: parsePositiveInt(
      "KASPA_HTTP_RATE_CAPACITY",
      process.env.KASPA_HTTP_RATE_CAPACITY,
      60,
    ),
    httpRateRefillPerSec: parsePositiveNumber(
      "KASPA_HTTP_RATE_REFILL_PER_SEC",
      process.env.KASPA_HTTP_RATE_REFILL_PER_SEC,
      2,
    ),
    signingRateCapacity: parsePositiveInt(
      "KASPA_SIGNING_RATE_CAPACITY",
      process.env.KASPA_SIGNING_RATE_CAPACITY,
      5,
    ),
    signingRateRefillPerSec: parsePositiveNumber(
      "KASPA_SIGNING_RATE_REFILL_PER_SEC",
      process.env.KASPA_SIGNING_RATE_REFILL_PER_SEC,
      5 / 60,
    ),
    previewRateCapacity: parsePositiveInt(
      "KASPA_PREVIEW_RATE_CAPACITY",
      process.env.KASPA_PREVIEW_RATE_CAPACITY,
      10,
    ),
    previewRateRefillPerSec: parsePositiveNumber(
      "KASPA_PREVIEW_RATE_REFILL_PER_SEC",
      process.env.KASPA_PREVIEW_RATE_REFILL_PER_SEC,
      10 / 60,
    ),
    maxPendingTx: parsePositiveInt(
      "KASPA_MAX_PENDING_TX",
      process.env.KASPA_MAX_PENDING_TX,
      50,
    ),
  };

  return Object.freeze(policy);
}

/**
 * Strictly positive safe integer parser. Used for bucket capacities, which
 * must be > 0 (a zero-capacity bucket bricks the path; a huge non-safe
 * integer would silently lose precision in arithmetic). Names like
 * `KASPA_HTTP_RATE_CAPACITY=0` will fail at startup rather than silently
 * blocking every request.
 */
function parsePositiveInt(name: string, raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw === "") return fallback;
  if (!/^\d+$/.test(raw)) {
    throw new Error(`${name} must be a positive integer, got "${raw}"`);
  }
  const v = Number(raw);
  if (!Number.isSafeInteger(v) || v <= 0) {
    throw new Error(
      `${name} must be a positive safe integer (> 0, ≤ Number.MAX_SAFE_INTEGER), got "${raw}"`
    );
  }
  return v;
}

/**
 * Non-negative decimal parser. Used for refill rates, where 0 is a valid
 * test configuration (drain the bucket and never refill it).
 */
function parsePositiveNumber(name: string, raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw === "") return fallback;
  // Allow decimals (refill rates like 0.0833 for 5/min).
  if (!/^\d+(\.\d+)?$/.test(raw)) {
    throw new Error(`${name} must be a non-negative decimal, got "${raw}"`);
  }
  const v = Number(raw);
  if (!Number.isFinite(v) || v < 0) {
    throw new Error(`${name} must be a non-negative number, got "${raw}"`);
  }
  return v;
}

export const policy: Policy = buildPolicy();
