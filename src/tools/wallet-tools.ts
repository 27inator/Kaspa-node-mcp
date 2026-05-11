/**
 * Wallet and transaction MCP tools.
 *
 * Wallet can be activated via:
 *   1. Startup unlock from ~/.kaspa-mcp/wallet.enc (TTY prompt or
 *      KASPA_WALLET_PASSWORD env). Requires KASPA_ENABLE_SIGNING=1 or
 *      KASPA_ENABLE_WALLET_SETUP=1. See services/wallet-unlock.ts.
 *   2. KASPA_MNEMONIC or KASPA_PRIVATE_KEY environment variables.
 *   3. kaspa_generate_mnemonic — creates and auto-activates a new wallet.
 *
 * Tools: address derivation, mnemonic generation, encrypted wallet save,
 * transaction sending, and fee estimation. The old kaspa_load_wallet tool
 * was removed in Phase 2 — passing a password through a tool argument
 * exposes it to the LLM transcript.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { createHash } from "node:crypto";
import * as kaspa from "kaspa-wasm";
import { KaspaWrpcClient } from "../services/kaspa-client.js";
import {
  getWallet,
  isWalletConfigured,
  setWalletInstance,
  KaspaWallet,
  type NetworkTypeName,
} from "../services/wallet.js";
import { sendKaspa, buildPreview, signAndSubmit } from "../services/transaction.js";
import { createPending, consumePending } from "../services/confirmations.js";
import {
  resolveApproval,
  makeApprovalChannel,
  type ApprovalChannel,
} from "../services/approval.js";
import { TokenBucket } from "../services/rate-limit.js";
import { audit, auditRateLimited, tokenHash } from "../services/audit.js";
import { PendingCapReachedError } from "../services/confirmations.js";
import {
  saveEncryptedWallet,
  walletFileExists,
  getWalletFilePath,
} from "../services/wallet-store.js";
import { policy } from "../services/policy.js";
import {
  validateKaspaAddress,
  prefixForNetwork,
} from "../services/address-validator.js";
import {
  kaspaAddressLooseSchema,
  payloadSchema,
  priorityFeeSompiSchema,
  confirmTokenSchema,
} from "../validation.js";
import { tty } from "../services/tty.js";

const { Mnemonic } = kaspa;

// ── Helpers used by tool handlers (top-level for testability) ─────────

interface ToolTextResult {
  // SDK requires an index signature on tool results.
  [x: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

function jsonResult(payload: Record<string, unknown>, isError = false): ToolTextResult {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    ...(isError ? { isError: true } : {}),
  };
}

/**
 * Public-address-derived fingerprint. Returned to the model so an operator
 * can cross-check the active wallet against a written-down backup without
 * exposing any secret-derived material. NEVER substitute a hash of the
 * mnemonic — that would leak entropy from the seed.
 */
function publicFingerprint(network: string, address: string): string {
  return createHash("sha256")
    .update(`${network}:${address}`)
    .digest("hex")
    .slice(0, 16);
}

/**
 * Format the words + checksum block written to /dev/tty. The checksum is
 * a 16-char prefix of sha256(phrase) so the operator can verify a backup
 * matches; this string MUST stay confined to the TTY channel — including
 * it in the tool result would leak entropy.
 */
function formatMnemonicDisplay(
  phrase: string,
  address: string,
  network: string
): string {
  const words = phrase.split(/\s+/);
  const cols = 4;
  const rows = Math.ceil(words.length / cols);
  const lines: string[] = [];
  for (let r = 0; r < rows; r++) {
    const row: string[] = [];
    for (let c = 0; c < cols; c++) {
      const idx = c * rows + r;
      if (idx >= words.length) break;
      row.push(`${String(idx + 1).padStart(2, " ")}. ${words[idx]!.padEnd(10, " ")}`);
    }
    lines.push("  " + row.join(" "));
  }
  const backupChecksum = createHash("sha256")
    .update(phrase)
    .digest("hex")
    .slice(0, 16);
  const sep = "═".repeat(67);
  const sub = "─".repeat(67);
  return (
    `\n${sep}\n` +
    `KASPA WALLET MNEMONIC — write these words down NOW.\n` +
    `Network: ${network}\n` +
    `Address: ${address}\n` +
    `${sub}\n` +
    `${lines.join("\n")}\n` +
    `${sub}\n` +
    `Backup checksum (compare against your written-down copy):\n` +
    `   sha256[:16] = ${backupChecksum}\n` +
    `${sep}\n`
  );
}

const PROMPT_TIMEOUT_MS = 60_000;

// ── kaspa_generate_mnemonic handler ───────────────────────────────────
//
// Sequencing locked by Phase 3b review:
//   1. Refuse without TTY (mnemonic must reach a model-invisible channel).
//   2. Refuse to overwrite an existing wallet file (loud, not silent).
//   3. Acquire encryption password (env preferred when set, TTY otherwise).
//      Fail BEFORE generating words if password unobtainable.
//   4. Generate mnemonic in memory.
//   5. Derive wallet (verifies the words produce a valid keypair).
//   6. Encrypt + write file. If this fails, no display has happened — the
//      operator never sees plaintext words.
//   7. Display words + backup checksum on /dev/tty. If this fails AFTER a
//      successful write, the tool result must explicitly say so.
//   8. Activate wallet for the session.
//   9. Compute address-derived public fingerprint.
//  10. Return {status, path, address, fingerprint}. Words are NEVER in
//      the result.
//
// JS string zeroing note: phrase strings are immutable in JS and kaspa-wasm
// internals may hold copies. Dropping local references is best-effort GC
// help, not a guarantee of in-process secret erasure.

export async function generateMnemonicHandler(args: {
  wordCount?: 12 | 24;
  network?: NetworkTypeName;
}): Promise<ToolTextResult> {
  const words = args.wordCount ?? 24;
  const net = (args.network ?? "testnet-12") as NetworkTypeName;

  // 1. Refuse without TTY.
  if (!tty.isTtyAvailable()) {
    return jsonResult(
      {
        error:
          "/dev/tty unavailable. kaspa_generate_mnemonic must display the " +
          "mnemonic on a terminal the model cannot observe; restart the " +
          "server from a terminal session.",
      },
      true,
    );
  }

  // 2. Refuse to overwrite.
  if (walletFileExists()) {
    const path = getWalletFilePath();
    return jsonResult(
      {
        error:
          `Existing wallet at ${path} would be overwritten. Move it aside ` +
          `first, then retry:\n  mv ${path} ${path}.bak.$(date +%s)`,
      },
      true,
    );
  }

  // 3. Acquire password BEFORE generating words.
  let password: string | null = null;
  if (policy.walletPasswordEnv) {
    password = policy.walletPasswordEnv;
  } else {
    try {
      password = await tty.promptPassword("Encryption password: ", {
        timeoutMs: PROMPT_TIMEOUT_MS,
      });
    } catch (e) {
      return jsonResult(
        {
          error:
            `password prompt failed: ${e instanceof Error ? e.message : String(e)}. ` +
            `Set KASPA_WALLET_PASSWORD or restart from a terminal.`,
        },
        true,
      );
    }
  }
  if (!password || password.length === 0) {
    return jsonResult(
      { error: "no password provided. Refusing to encrypt with empty password." },
      true,
    );
  }

  // 4. Generate mnemonic. Track the reference so we can drop it on exit.
  const mnemonic = Mnemonic.random(words);
  let phrase: string | null = mnemonic.phrase;

  try {
    // 5. Derive wallet.
    const wallet = KaspaWallet.fromMnemonic(phrase, net, 0);
    const address = wallet.getAddress();

    // 6. Encrypt + write file. If this throws, no display has occurred.
    saveEncryptedWallet(phrase, password, net, 0);

    // 7. Display words on /dev/tty only.
    const displayText = formatMnemonicDisplay(phrase, address, net);
    try {
      await tty.writeMnemonic(displayText);
    } catch (e) {
      // File written, words not displayed. Activate the wallet so the
      // session can still proceed but warn loudly.
      setWalletInstance(wallet);
      return jsonResult(
        {
          status: "saved-but-not-displayed",
          path: getWalletFilePath(),
          network: net,
          address,
          warning:
            `Encrypted wallet was saved to ${getWalletFilePath()} but the ` +
            `mnemonic could NOT be displayed on /dev/tty ` +
            `(${e instanceof Error ? e.message : String(e)}). ` +
            `If you don't already have a written-down backup, move the file ` +
            `aside and re-run:\n  mv ${getWalletFilePath()} ${getWalletFilePath()}.bak.$(date +%s)`,
        },
        true,
      );
    }

    // 8. Activate wallet.
    setWalletInstance(wallet);

    // 9. Public, address-derived fingerprint.
    const fingerprint = publicFingerprint(net, address);

    // 10. Return.
    return jsonResult({
      status: "saved",
      path: getWalletFilePath(),
      network: net,
      address,
      fingerprint,
      message:
        "Mnemonic was displayed on /dev/tty only — write it down. The " +
        "fingerprint above is derived from the public address; it is safe " +
        "to log and lets you cross-check that the right wallet is active.",
    });
  } finally {
    // Best-effort secret cleanup. JS strings are immutable, kaspa-wasm
    // internals may retain copies, and GC is non-deterministic — this is
    // not a guarantee of in-process erasure, just a hint.
    phrase = null;
    password = null;
    void phrase; void password;
  }
}

// Process-global signing-side rate limit. Gates kaspa_confirm_send_transaction
// BEFORE consumePending so a denial doesn't burn a valid token. Sized for
// a human approver: defaults to 5 capacity + ~5/min refill.
const signingBucket = new TokenBucket(
  policy.signingRateCapacity,
  policy.signingRateRefillPerSec,
);

// Process-global preview-side rate limit. Gates kaspa_send_transaction so
// stdio-mode launches (no HTTP rate limit) cannot have a model spam
// preview creation — each preview costs an RPC round trip AND a pending-
// map slot. Defaults are looser than signing (10 capacity, 10/min refill)
// because preview is supposed to be more frequent than confirm.
const previewBucket = new TokenBucket(
  policy.previewRateCapacity,
  policy.previewRateRefillPerSec,
);

/** Test affordance: drain the signing bucket. */
export function _drainSigningBucketForTests(): void {
  signingBucket._drainForTests();
}
/** Test affordance: drain the preview bucket. */
export function _drainPreviewBucketForTests(): void {
  previewBucket._drainForTests();
}
/** Test affordance: reconfigure rates so a single section can test denials
 *  even when other sections rely on a high default rate. */
export function _reconfigureSigningBucketForTests(capacity: number, refillPerSec: number): void {
  signingBucket._reconfigureForTests(capacity, refillPerSec);
}
export function _reconfigurePreviewBucketForTests(capacity: number, refillPerSec: number): void {
  previewBucket._reconfigureForTests(capacity, refillPerSec);
}

// ── kaspa_send_transaction handler (Phase 3e: PREVIEW only) ──────────
//
// Constraints (Phase 3e):
//   - Builds a transaction preview, stores it in the module-singleton
//     pending map, returns a confirm_token. Does NOT sign, does NOT
//     submit. The only path to a real broadcast is
//     kaspa_confirm_send_transaction with the matching token.
//   - All cap / checksum / payload validation lives in buildPreview, not
//     here. The tool layer is just the schema + wallet check.
//   - Stderr write of the preview + token + digest goes to the operator's
//     MCP-server log so they can see what the model just queued.

interface SendTxArgs {
  to: string;
  amount: string;
  priorityFee?: number;
  payload?: string;
}

export async function sendTransactionHandler(
  args: SendTxArgs,
): Promise<ToolTextResult> {
  // Rate-limit at the preview boundary BEFORE wallet checks, RPC work,
  // or pending-map writes. Otherwise a model in stdio mode (no HTTP
  // bucket) can spam preview creation, burning RPC calls and filling
  // the pending map. Auditing is bucketed (audit.ts auditRateLimited)
  // so a flood of denials does not turn into a flood of disk writes.
  if (!previewBucket.consume()) {
    auditRateLimited("preview");
    return jsonResult(
      {
        error: "preview rate limit exceeded; retry shortly",
      },
      true,
    );
  }

  if (!isWalletConfigured()) {
    return jsonResult(
      {
        error:
          "No active wallet. Set KASPA_MNEMONIC or generate one with " +
          "kaspa_generate_mnemonic (requires KASPA_ENABLE_WALLET_SETUP=1).",
      },
      true,
    );
  }

  // kasToSompi can throw on bad-decimal input (the schema already rejects
  // most cases, but defense-in-depth).
  let amountSompi: bigint;
  try {
    amountSompi = kasToSompi(args.amount);
  } catch (e) {
    return jsonResult(
      { error: e instanceof Error ? e.message : String(e) },
      true,
    );
  }
  const priorityFeeSompi = BigInt(args.priorityFee ?? 0);

  // buildPreview re-validates everything (cap, recipient checksum, payload
  // shape, min-output, balance, sync) and returns a JSON params bundle.
  let preview;
  try {
    preview = await buildPreview({
      to: args.to,
      amountSompi,
      priorityFeeSompi,
      ...(args.payload ? { payload: args.payload } : {}),
    });
  } catch (e) {
    return jsonResult(
      {
        error: e instanceof Error ? e.message : String(e),
        hint: "preview failed — no pending entry was created",
      },
      true,
    );
  }

  // Store pending in the module singleton; survives across HTTP per-request
  // McpServer instances by ESM module-scope semantics. May throw
  // PendingCapReachedError if the map is full — surface that explicitly
  // so the operator knows to wait or restart.
  let token: string;
  let digest: string;
  let expiresAt: number;
  try {
    ({ token, digest, expiresAt } = createPending(
      preview.params,
      preview.feeSompi,
      preview.previewText,
    ));
  } catch (e) {
    if (e instanceof PendingCapReachedError) {
      audit("pending_cap_reached", { cap: e.cap, current: e.current });
      return jsonResult(
        {
          error:
            `pending-tx cap reached (${e.current}/${e.cap}). Wait for ` +
            `existing tokens to expire (5 min) or restart the server.`,
        },
        true,
      );
    }
    throw e;
  }

  // Operator log so the human running the MCP server can see what was
  // queued without trusting the model to surface it faithfully.
  console.error("[kaspa-mcp] kaspa_send_transaction preview:");
  console.error(preview.previewText);
  console.error(
    `[kaspa-mcp] confirm_token=${token} digest=${digest} ` +
      `expires=${new Date(expiresAt).toISOString()}`,
  );

  // Audit: record what got queued WITHOUT logging the raw token.
  audit("send_preview_created", {
    tokenHash: tokenHash(token),
    digest,
    network: preview.params.network,
    to: preview.params.to,
    amountSompi: preview.params.amountSompi,
    priorityFeeSompi: preview.params.priorityFeeSompi,
    feeSompiEstimate: preview.feeSompi,
    payloadBytes: preview.params.payload
      ? preview.params.payload.length / 2
      : 0,
    senderAddress: preview.params.senderAddress,
    expiresAt: new Date(expiresAt).toISOString(),
  });

  return jsonResult({
    status: "preview_pending_confirmation",
    confirm_token: token,
    digest,
    preview: preview.previewText,
    expires_at: new Date(expiresAt).toISOString(),
    message:
      "Preview only — nothing was signed or broadcast. Call " +
      "kaspa_confirm_send_transaction with this confirm_token to ask " +
      "the user for approval (via MCP elicitation if the client supports " +
      "it, otherwise a /dev/tty prompt). The user, not the model, makes " +
      "the actual decision.",
  });
}

// ── kaspa_confirm_send_transaction handler ────────────────────────────
//
// Only path that calls signAndSubmit. Validates token format, consumes
// the pending entry (delete + return), resolves approval through the
// channel (elicitation → TTY), then signs and submits.
//
// Single-use is enforced by consumePending (which deletes regardless of
// success). Any retry against the same token returns the generic
// "unknown / expired / used" error.

interface ConfirmSendArgs {
  confirm_token: string;
}

export interface ConfirmSendDeps {
  channel: ApprovalChannel;
  // submit injection lets tests substitute a mocked signer without touching
  // the real Kaspa node; production passes the real signAndSubmit.
  submit?: typeof signAndSubmit;
}

export async function confirmSendTransactionHandler(
  args: ConfirmSendArgs,
  deps: ConfirmSendDeps,
): Promise<ToolTextResult> {
  // 0. Rate limit BEFORE consumePending. A denied confirm must not burn
  //    a valid token; the operator can retry within the window. The
  //    bucket is process-global; per-token rate-limiting would invert
  //    the invariant (a malicious model could lock out a legitimate
  //    operator by exhausting a wrong-token quota).
  if (!signingBucket.consume()) {
    // Bucketed audit for consistency with the HTTP / preview paths — a
    // model spamming confirm calls would otherwise drive sync disk
    // writes per denial.
    auditRateLimited("signing");
    return jsonResult(
      {
        error: "signing rate limit exceeded; retry shortly",
      },
      true,
    );
  }

  // 1. Validate token format up front. We use the same generic error
  //    message for any unknown/expired/used/malformed token so an attacker
  //    cannot use the response to differentiate "used recently" from
  //    "never existed".
  const parsed = confirmTokenSchema.safeParse(args.confirm_token);
  if (!parsed.success) {
    audit("confirm_failed", { reason: "bad_token_format" });
    return jsonResult(
      {
        error: "confirm_token unknown, expired, or already used",
      },
      true,
    );
  }

  // 2. Consume (atomic get + delete).
  const entry = consumePending(parsed.data);
  if (!entry) {
    audit("confirm_failed", {
      reason: "unknown_or_expired",
      tokenHash: tokenHash(parsed.data),
    });
    return jsonResult(
      { error: "confirm_token unknown, expired, or already used" },
      true,
    );
  }

  // 3. Resolve approval. The pending entry is already deleted at this
  //    point — denial / failure paths must NOT undelete (single-use).
  const approval = await resolveApproval(
    deps.channel,
    entry.preview,
    entry.digest,
  );

  if (!approval.approved) {
    audit("confirm_attempted", {
      tokenHash: tokenHash(parsed.data),
      digest: entry.digest,
      approved: false,
      reason: approval.reason,
    });
    return jsonResult(
      {
        error: `transaction not approved: ${approval.reason}`,
        reason: approval.reason,
      },
      true,
    );
  }

  // 4. Submit. signAndSubmit re-validates the params bundle and re-fetches
  //    UTXOs fresh — the preview is only a state-machine handle, not a
  //    snapshot.
  audit("confirm_attempted", {
    tokenHash: tokenHash(parsed.data),
    digest: entry.digest,
    approved: true,
    method: approval.method,
  });
  const submitFn = deps.submit ?? signAndSubmit;
  try {
    const result = await submitFn(entry.params);
    console.error(
      `[kaspa-mcp] kaspa_confirm_send_transaction submitted: ` +
        `txId=${result.txId} fee=${result.fee} via=${approval.method}`,
    );
    audit("confirm_submitted", {
      tokenHash: tokenHash(parsed.data),
      digest: entry.digest,
      txId: result.txId,
      fee: result.fee,
      totalTransactions: result.totalTransactions,
      method: approval.method,
    });
    return jsonResult({
      status: "submitted",
      txId: result.txId,
      fee: result.fee,
      totalTransactions: result.totalTransactions,
      approvalMethod: approval.method,
      digest: entry.digest,
    });
  } catch (e) {
    audit("confirm_failed", {
      tokenHash: tokenHash(parsed.data),
      digest: entry.digest,
      reason: "submit_error",
      method: approval.method,
    });
    return jsonResult(
      {
        error: `submit failed: ${e instanceof Error ? e.message : String(e)}`,
        approvalMethod: approval.method,
      },
      true,
    );
  }
}

// ── kaspa_save_wallet handler ─────────────────────────────────────────
//
// Constraints (Phase 3c):
//   - Schema is {} — password never travels through a tool argument.
//   - Order: refuse-overwrite → wallet-state checks → password acquisition
//     → save. We don't prompt for a password if we wouldn't be saving
//     anything anyway.
//   - Password source: env first when set (matches unlock for consistency,
//     and surfaces a "less preferred than TTY" log line); TTY otherwise.
//     If both are unavailable, refuse with a clear remediation hint.
//   - Empty password is rejected (whether from env or TTY).
//   - Private-key-only wallets stay unsaveable.
//   - On overwrite refusal: same `mv ... .bak.$(date +%s)` recovery hint
//     as kaspa_generate_mnemonic.
//
// Deps injection: production reads the env via policy. Tests pass an
// explicit `envPassword` to exercise both env-set and env-unset paths
// in-process without spawning subprocesses with different env.

export interface SaveWalletDeps {
  envPassword: string | undefined;
}

const PROMPT_TIMEOUT_MS_SAVE = 60_000;

export async function saveWalletHandler(
  _args: Record<string, never> = {},
  deps: SaveWalletDeps = { envPassword: policy.walletPasswordEnv },
): Promise<ToolTextResult> {
  // 1. Wallet state checks first — no point in any password work if we
  //    have nothing to save.
  if (!isWalletConfigured()) {
    return jsonResult(
      {
        error:
          "No active wallet. Generate one with kaspa_generate_mnemonic " +
          "(requires KASPA_ENABLE_WALLET_SETUP=1) or set KASPA_MNEMONIC " +
          "env var, then retry.",
      },
      true,
    );
  }
  const wallet = getWallet();
  const mnemonic = wallet.getMnemonic();
  if (!mnemonic) {
    return jsonResult(
      {
        error:
          "Cannot save: wallet was loaded from a raw private key, not a " +
          "BIP39 mnemonic. Only mnemonic-based wallets can be persisted.",
      },
      true,
    );
  }

  // 2. Refuse overwrite. Same loud, exact recovery path as 3b.
  if (walletFileExists()) {
    const path = getWalletFilePath();
    return jsonResult(
      {
        error:
          `Existing wallet at ${path} would be overwritten. Move it aside ` +
          `first, then retry:\n  mv ${path} ${path}.bak.$(date +%s)`,
      },
      true,
    );
  }

  // 3. Acquire password: env first, TTY fallback.
  let password: string | null = null;
  let passwordSource: "env" | "tty";
  if (deps.envPassword && deps.envPassword.length > 0) {
    password = deps.envPassword;
    passwordSource = "env";
    console.error(
      "[kaspa-mcp] kaspa_save_wallet: using KASPA_WALLET_PASSWORD env. " +
        "Note: env vars can leak via shell history / process inspection — " +
        "prefer TTY for interactive setups.",
    );
  } else if (tty.isTtyAvailable()) {
    passwordSource = "tty";
    try {
      password = await tty.promptPassword("Encryption password: ", {
        timeoutMs: PROMPT_TIMEOUT_MS_SAVE,
      });
    } catch (e) {
      return jsonResult(
        {
          error:
            `password prompt failed: ${e instanceof Error ? e.message : String(e)}. ` +
            `Set KASPA_WALLET_PASSWORD or restart from a terminal.`,
        },
        true,
      );
    }
  } else {
    return jsonResult(
      {
        error:
          "No password source available. Set KASPA_WALLET_PASSWORD env, " +
          "or restart the server from a terminal so /dev/tty is available.",
      },
      true,
    );
  }

  // 4. Empty password — fail closed regardless of source.
  if (!password || password.length === 0) {
    return jsonResult(
      {
        error:
          "Empty password. Refusing to encrypt the wallet with an empty " +
          "password. Set a non-empty KASPA_WALLET_PASSWORD or type one at " +
          "the prompt.",
      },
      true,
    );
  }

  try {
    // 5. Encrypt + write. saveEncryptedWallet writes atomically (creates
    //    the dir if missing, chmods the file 600).
    saveEncryptedWallet(
      mnemonic,
      password,
      wallet.getNetworkId(),
      wallet.getAccountIndex(),
    );

    // 6. Success. Public, address-derived fingerprint.
    const address = wallet.getAddress();
    const network = wallet.getNetworkId();
    return jsonResult({
      status: "saved",
      path: getWalletFilePath(),
      network,
      address,
      fingerprint: publicFingerprint(network, address),
      passwordSource,
      message:
        "Wallet encrypted and saved. Future sessions unlock at startup via " +
        "/dev/tty (preferred) or KASPA_WALLET_PASSWORD env (server must be " +
        "launched with KASPA_ENABLE_SIGNING=1 or KASPA_ENABLE_WALLET_SETUP=1).",
    });
  } finally {
    // Best-effort secret cleanup. Same caveat as generate: JS strings are
    // immutable; this is GC help, not erasure.
    password = null;
    void password;
  }
}

const SOMPI_PER_KAS = 100_000_000n;
const MAX_DECIMAL_PLACES = 8;

/**
 * Decimal-KAS string ("1.5", "100", "0.001") → sompi bigint.
 *
 * Rejects malformed strings, > 8 decimal places, and zero/negative amounts.
 * Caller is responsible for applying the per-tx cap (see policy.maxSompiPerTx).
 */
function kasToSompi(amountStr: string): bigint {
  const trimmed = amountStr.trim();
  if (!/^\d+(\.\d+)?$/.test(trimmed)) {
    throw new Error("amount must be a valid decimal number");
  }

  const parts = trimmed.split(".");
  const integerPart = parts[0];
  let fractionalPart = parts[1] || "";

  if (fractionalPart.length > MAX_DECIMAL_PLACES) {
    throw new Error(
      `amount cannot have more than ${MAX_DECIMAL_PLACES} decimal places`
    );
  }

  fractionalPart = fractionalPart.padEnd(MAX_DECIMAL_PLACES, "0");
  const sompi = BigInt(integerPart) * SOMPI_PER_KAS + BigInt(fractionalPart);

  if (sompi <= 0n) {
    throw new Error("amount must be greater than zero");
  }

  return sompi;
}

/**
 * Address validator scoped to the current wallet's network. Wraps the shared
 * runtime validator so we get checksum verification + a network-mismatch
 * message that names the configured wallet network.
 */
function validateAddressForActiveWallet(address: string): void {
  const wallet = getWallet();
  const expectedPrefix = prefixForNetwork(wallet.getNetworkType());
  try {
    validateKaspaAddress(address, expectedPrefix);
  } catch (e) {
    throw new Error(
      `${e instanceof Error ? e.message : String(e)} ` +
        `(wallet is on ${wallet.getNetworkId()})`
    );
  }
}

export function registerWalletTools(
  server: McpServer,
  client: KaspaWrpcClient
): void {
  // ── Wallet Address ──────────────────────────────────────────────────

  server.registerTool(
    "kaspa_get_my_address",
    {
      title: "Get My Wallet Address",
      description: `Get the Kaspa address derived from the active wallet.

Requires an active wallet — unlock the encrypted wallet at startup (KASPA_ENABLE_SIGNING=1 plus TTY/env password), set KASPA_MNEMONIC/KASPA_PRIVATE_KEY env var, or generate one with kaspa_generate_mnemonic.

Returns:
  - address: the derived Kaspa address (kaspa: or kaspatest: prefix)
  - network: which network the wallet is configured for`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async () => {
      if (!isWalletConfigured()) {
        const hint = walletFileExists()
          ? "Encrypted wallet found. Restart the server with KASPA_ENABLE_SIGNING=1 to unlock at startup (TTY prompt or KASPA_WALLET_PASSWORD env)."
          : "Use kaspa_generate_mnemonic (with KASPA_ENABLE_WALLET_SETUP=1) or set KASPA_MNEMONIC env var.";
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  error: `No active wallet. ${hint}`,
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        };
      }

      const wallet = getWallet();
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                address: wallet.getAddress(),
                network: wallet.getNetworkId(),
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // ── Send Transaction (gated: KASPA_ENABLE_SIGNING=1) ────────────────
  // Two-step flow:
  //   1. kaspa_send_transaction  → build preview, store pending entry,
  //                                return confirm_token. NO sign, NO submit.
  //   2. kaspa_confirm_send_transaction → consume token, ask user via
  //                                       elicitation/TTY, then submit.
  // The signing tools are only registered when KASPA_ENABLE_SIGNING=1 so
  // a server launched without signing does not even advertise them.
  // Pending state lives in services/confirmations.ts as a module-singleton
  // so it survives across HTTP per-request McpServer instances.
  if (policy.enableSigning) {
  const channel = makeApprovalChannel(server);

  server.registerTool(
    "kaspa_send_transaction",
    {
      title: "Send KAS Transaction (Step 1: Preview)",
      description: `Build a Kaspa transaction PREVIEW and stage it for human approval. Does NOT sign or broadcast.

This is step 1 of a two-step flow. The tool returns a confirm_token; the model must then call kaspa_confirm_send_transaction with that token. Approval is collected from the user via MCP elicitation (preferred) or a /dev/tty prompt — never from the model.

Requires an active wallet — unlock the encrypted wallet at startup (KASPA_ENABLE_SIGNING=1 plus TTY/env password), set KASPA_MNEMONIC env var, or generate one with kaspa_generate_mnemonic.

Args:
  - to: recipient Kaspa address
  - amount: amount to send in KAS (e.g. "1.5" or "100")
  - priorityFee: optional priority fee in sompi (default: 0)
  - payload: optional hex-encoded transaction payload (max 20kB)

Returns:
  - confirm_token: 32-hex handle to pass to kaspa_confirm_send_transaction
  - digest: 8-hex transaction-identity digest the user will type to approve
  - preview: human-readable summary the model should surface verbatim
  - expires_at: ISO timestamp; tokens are single-use and expire in 5 min`,
      inputSchema: {
        to: kaspaAddressLooseSchema.describe(
          "Recipient Kaspa address (kaspa: or kaspatest: prefix). Checksum is verified server-side."
        ),
        amount: z
          .string()
          .max(40, "amount string too long")
          .describe("Amount to send in KAS (e.g. '1.5', '100', '0.001')"),
        priorityFee: priorityFeeSompiSchema
          .optional()
          .describe("Priority fee in sompi (optional, default: 0)"),
        payload: payloadSchema
          .optional()
          .describe("Hex-encoded transaction payload (optional, capped at 20kB)"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false, // preview only
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args) => sendTransactionHandler(args),
  );

  server.registerTool(
    "kaspa_confirm_send_transaction",
    {
      title: "Confirm KAS Transaction (Step 2: Sign + Broadcast)",
      description: `Step 2 of the send flow. Consumes the confirm_token from kaspa_send_transaction, asks the user to approve via MCP elicitation or /dev/tty, then signs and broadcasts.

Approval channel: tries MCP elicitation first; falls back to /dev/tty prompt with exact "APPROVE <digest>" match. If neither channel is available (headless launch with non-elicitation client), the call refuses rather than broadcasting.

Tokens are SINGLE-USE — they are deleted whether the call succeeds, the user declines, the TTY phrase mismatches, or the submit fails.

Args:
  - confirm_token: 32-hex token returned by kaspa_send_transaction

Returns on success:
  - txId: submitted transaction id
  - fee: total fees paid in KAS
  - approvalMethod: "elicitation" or "tty"
  - digest: same 8-hex digest the user approved`,
      inputSchema: {
        confirm_token: z
          .string()
          .describe("32-hex confirm_token returned by kaspa_send_transaction"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args) => confirmSendTransactionHandler(args, { channel }),
  );
  } // end if (policy.enableSigning)

  // ── Generate Mnemonic (gated: KASPA_ENABLE_WALLET_SETUP=1) ──────────
  // Setup tools are dangerous — they create long-lived secrets and put a
  // wallet into the active session. The handler implementation lives at
  // module scope (generateMnemonicHandler) so tests can call it directly
  // with a swapped TTY impl; here we just register it.
  if (policy.enableWalletSetup) {
  server.registerTool(
    "kaspa_generate_mnemonic",
    {
      title: "Generate New Mnemonic",
      description: `Generate a new BIP39 mnemonic, encrypt it to ~/.kaspa-mcp/wallet.enc, and activate it for this session.

The mnemonic is displayed on /dev/tty only — it is NEVER returned to the model. Requires a real terminal; refuses to run in headless mode. Refuses to overwrite an existing wallet file.

Encryption password comes from KASPA_WALLET_PASSWORD env (when set) or a /dev/tty prompt (otherwise). Empty passwords are rejected.

Args:
  - wordCount: 12 or 24 words (default: 24)
  - network: network for address derivation (default: testnet-12)

Returns:
  - status: "saved" or "saved-but-not-displayed"
  - path: encrypted wallet file path
  - address: derived Kaspa address
  - fingerprint: 16-hex-char sha256 of "<network>:<address>" — public,
    safe to log, lets the operator cross-check the active wallet`,
      inputSchema: {
        wordCount: z
          .union([z.literal(12), z.literal(24)])
          .optional()
          .describe("Number of words: 12 or 24 (default: 24)"),
        network: z
          .enum(["mainnet", "testnet-10", "testnet-11", "testnet-12"])
          .optional()
          .describe("Network for address derivation (default: testnet-12)"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    generateMnemonicHandler,
  );
  } // end if (policy.enableWalletSetup) — generate_mnemonic

  // ── Fee Estimate ────────────────────────────────────────────────────

  server.registerTool(
    "kaspa_estimate_fee",
    {
      title: "Estimate Transaction Fee",
      description: `Get current fee estimates from the connected Kaspa node. Returns priority, normal, and low fee buckets with estimated confirmation times.

Returns:
  - priorityBucket: highest-priority fee rate and estimated seconds
  - normalBuckets: normal fee rate tiers
  - lowBuckets: low fee rate tiers`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async () => {
      try {
        const data = await client.request("getFeeEstimate");
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(data, null, 2),
            },
          ],
        };
      } catch (error) {
        // Some node versions may not support getFeeEstimate
        const message =
          error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  error: `Fee estimation failed: ${message}`,
                  hint: "This RPC method may not be available on all node versions.",
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        };
      }
    }
  );

  // ── Save Wallet (gated: KASPA_ENABLE_WALLET_SETUP=1) ────────────────
  // Schema is {} — password is acquired via env (preferred for headless)
  // or /dev/tty (preferred for interactive setup). The handler lives at
  // module scope (saveWalletHandler) for in-process testability; here we
  // wrap it to ignore the SDK's `extra` arg so the deps default fires.
  if (policy.enableWalletSetup) {
  server.registerTool(
    "kaspa_save_wallet",
    {
      title: "Save Wallet (Encrypted)",
      description: `Encrypt the active wallet's mnemonic with AES-256-GCM and save to ~/.kaspa-mcp/wallet.enc (chmod 600).

Key derivation: scrypt (N=65536, r=8, p=1). Refuses to overwrite an existing wallet file.

Password source: KASPA_WALLET_PASSWORD env when set (less preferred — env vars can leak via shell history / process inspection), otherwise a /dev/tty prompt. Empty passwords are rejected.

Requires an active wallet with a mnemonic (from kaspa_generate_mnemonic or KASPA_MNEMONIC env var). Wallets loaded from a raw private key cannot be saved.

Next session, the server unlocks the wallet at startup via /dev/tty (preferred) or KASPA_WALLET_PASSWORD env (requires KASPA_ENABLE_SIGNING=1 or KASPA_ENABLE_WALLET_SETUP=1).`,
      inputSchema: {},
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async (args) => saveWalletHandler(args),
  );
  } // end if (policy.enableWalletSetup) — save_wallet

  // ── Load Wallet ──────────────────────────────────────────────────────
  //
  // Removed in Phase 2. Unlock now happens at server startup via
  // /dev/tty (preferred) or KASPA_WALLET_PASSWORD env (fallback). The
  // password no longer travels through a tool argument because tool args
  // pass through the LLM's context window, where they may be cached or
  // logged. See services/wallet-unlock.ts.
}
