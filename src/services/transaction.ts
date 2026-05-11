/**
 * Transaction building and submission module.
 *
 * Phase 4.5 split:
 *   - buildPreview()   — fetches UTXOs, runs the WASM Generator, returns a
 *                        plain-JSON parameter bundle + fee estimate. NO
 *                        signing, NO broadcast, NO WASM objects retained.
 *   - signAndSubmit()  — re-fetches UTXOs (freshness guarantee), rebuilds
 *                        the Generator, signs each pending tx with the
 *                        active wallet, submits to the node.
 *   - sendKaspa()      — thin wrapper that runs build → submit. Kept so
 *                        Phase 4's caller in wallet-tools.ts stays working;
 *                        Phase 3 will replace its caller with the two-step
 *                        confirmation flow that consumes buildPreview()
 *                        directly.
 *
 * Each entry point owns its own ephemeral kaspa-wasm RpcClient and
 * disconnects it in `finally`. We do not share a long-lived signing client
 * because the WASM RpcClient is bound to a specific networkId at construction
 * time and the wallet (which determines that network) can change at runtime
 * via kaspa_load_wallet.
 */

import * as kaspa from "kaspa-wasm";
import { getWallet } from "./wallet.js";
import { policy } from "./policy.js";
import { validateKaspaAddress } from "./address-validator.js";

const {
  Generator,
  RpcClient,
  Encoding,
  sompiToKaspaString,
  Address,
  estimateTransactions,
} = kaspa;

const CONNECT_TIMEOUT_MS = 30_000;

// ── Test-only mock seam ───────────────────────────────────────────────
//
// When KASPA_TEST_MOCK_TXSERVICE=1, buildPreview and signAndSubmit return
// canned data WITHOUT touching the kaspa-wasm RPC client. This lets the
// HTTP two-request test prove that the pending map survives per-request
// McpServer instances without needing a live Kaspa node or a mock wRPC
// listener. It is gated behind an env var that emits a loud startup
// warning, and the value MUST never be set in production.
const TX_MOCK = process.env.KASPA_TEST_MOCK_TXSERVICE === "1";
if (TX_MOCK) {
  console.error(
    "[kaspa-mcp] *** KASPA_TEST_MOCK_TXSERVICE=1 — transaction service is " +
      "MOCKED. buildPreview/signAndSubmit return canned data; broadcasts do " +
      "NOT reach a Kaspa node. This must NEVER be enabled in production. ***"
  );
}

// TN12+ uses 3-dimensional mass (compute, storage, transient).
// Storage mass = C / output_value, so tiny outputs are extremely heavy.
// Reject amounts below 0.1 KAS to avoid "Storage mass exceeds maximum"
// errors from the Generator.
const MIN_OUTPUT_SOMPI = 10_000_000n; // 0.1 KAS

// ── Shared input validation ───────────────────────────────────────────
//
// signAndSubmit() is a load-bearing signing boundary. Even though Phase 3
// will only feed it server-generated TxParams, we validate every field
// before any RPC so a bug, refactor mistake, or future entry point cannot
// turn a malformed bundle into a real broadcast.

function assertString(field: string, raw: unknown): asserts raw is string {
  if (typeof raw !== "string") {
    throw new Error(`${field} must be a string (got ${typeof raw})`);
  }
}

function parseSompiField(field: string, raw: unknown): bigint {
  assertString(field, raw);
  if (!/^\d+$/.test(raw)) {
    throw new Error(
      `${field} must be a non-negative decimal integer (got "${raw}")`
    );
  }
  return BigInt(raw);
}

function checkAmounts(amountSompi: bigint, priorityFeeSompi: bigint): void {
  if (amountSompi <= 0n) {
    throw new Error("amount must be > 0");
  }
  if (priorityFeeSompi < 0n) {
    throw new Error("priorityFee cannot be negative");
  }
  if (amountSompi < MIN_OUTPUT_SOMPI) {
    throw new Error(
      `amount too small: minimum is 0.1 KAS (${MIN_OUTPUT_SOMPI} sompi) ` +
        `due to TN12 storage mass rules`
    );
  }
  // Cap applies to total spend so a high fee can't bypass the limit.
  const total = amountSompi + priorityFeeSompi;
  if (total > policy.maxSompiPerTx) {
    throw new Error(
      `total spend ${total} sompi (amount=${amountSompi} + ` +
        `fee=${priorityFeeSompi}) exceeds KASPA_MAX_SOMPI_PER_TX cap ` +
        `${policy.maxSompiPerTx} sompi`
    );
  }
}

function checkPayload(payload: unknown): void {
  if (payload === undefined || payload === null) return;
  if (typeof payload !== "string") {
    throw new Error(`payload must be a string (got ${typeof payload})`);
  }
  if (payload.length === 0) return;
  if (!/^[0-9a-fA-F]+$/.test(payload)) {
    throw new Error("payload must be hex-encoded");
  }
  if (payload.length % 2 !== 0) {
    throw new Error("payload hex length must be even");
  }
  if (payload.length > 20_000) {
    throw new Error("payload exceeds 20_000 hex chars");
  }
}

/**
 * Recipient validation scoped to a specific network. Runs the real CashAddr
 * checksum (via kaspa.Address) and refuses to send to an address whose prefix
 * doesn't match the network the preview was built for. Lives in the service
 * so Phase 3's direct callers don't have to re-implement it.
 */
function checkRecipient(to: unknown, networkId: string): void {
  assertString("to", to);
  const expectedPrefix: "kaspa" | "kaspatest" =
    networkId === "mainnet" ? "kaspa" : "kaspatest";
  try {
    validateKaspaAddress(to, expectedPrefix);
  } catch (e) {
    throw new Error(
      `recipient ${e instanceof Error ? e.message : String(e)} ` +
        `(network: ${networkId})`
    );
  }
}

function getBorshEndpoint(): string {
  return process.env.KASPA_BORSH_ENDPOINT ?? process.env.KASPA_ENDPOINT ?? "ws://127.0.0.1:17210";
}

function connectWithTimeout(
  rpc: { connect: (options: Record<string, never>) => Promise<void> },
  timeoutMs: number
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        reject(new Error("RPC connection timed out"));
      }
    }, timeoutMs);

    rpc.connect({}).then(
      () => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve();
        }
      },
      (err: unknown) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err);
        }
      }
    );
  });
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Create an ephemeral WASM RpcClient connected to the local node's Borsh
 * endpoint, scoped to the active wallet's network. Caller MUST disconnect
 * in a finally block.
 */
async function createRpcClient(): Promise<kaspa.RpcClient> {
  const wallet = getWallet();
  const rpc = new RpcClient({
    url: getBorshEndpoint(),
    encoding: Encoding.Borsh,
    networkId: wallet.getNetworkId(),
  });
  await connectWithTimeout(rpc, CONNECT_TIMEOUT_MS);
  return rpc;
}

// ── Plain JSON parameter bundle ───────────────────────────────────────

/**
 * Self-contained, JSON-serializable description of a pending transaction.
 *
 * Holds NO WASM objects, NO UTXO snapshots, NO PendingTransaction handles —
 * this is what the Phase 3 pending-tx map will store across the
 * preview-then-confirm boundary. signAndSubmit() re-derives all UTXO state
 * from these params at submit time so a stale preview cannot cause a
 * spend with stale inputs.
 *
 * bigints are encoded as decimal strings so the bundle round-trips cleanly
 * through JSON.stringify if we ever serialize it (e.g., for an audit log).
 */
export interface TxParams {
  to: string;
  amountSompi: string;       // bigint as decimal string
  priorityFeeSompi: string;  // bigint as decimal string
  payload?: string;          // hex
  network: string;           // network id captured at preview time
  senderAddress: string;     // captured at preview time
}

export interface BuildPreview {
  /** Human-readable summary suitable for stderr / TTY confirmation. */
  previewText: string;
  /** Fee estimate as decimal-string sompi. */
  feeSompi: string;
  /** How many chained txs the Generator would emit. */
  totalTransactions: number;
  /** Echoed back to signAndSubmit verbatim. */
  params: TxParams;
}

export interface SubmitResult {
  txId: string;
  fee: string;       // KAS string for human display
  totalTransactions: number;
}

// ── Internal: shared validation + UTXO fetch ──────────────────────────

interface FetchedContext {
  rpc: kaspa.RpcClient;
  entries: Array<{ amount: bigint }>;
  senderAddress: string;
}

async function preflight(
  to: string,
  amountSompi: bigint,
  priorityFeeSompi: bigint
): Promise<FetchedContext> {
  // checkAmounts() must have run before reaching here. Caller contract,
  // not silent — preflight focuses on RPC-dependent checks (sync, balance).

  const wallet = getWallet();
  const senderAddress = wallet.getAddress();
  const rpc = await createRpcClient();

  try {
    const { isSynced } = await rpc.getServerInfo();
    if (!isSynced) {
      throw new Error("node is not synced — cannot submit transactions");
    }

    const { entries } = await rpc.getUtxosByAddresses([
      new Address(senderAddress),
    ]);
    if (!entries || entries.length === 0) {
      throw new Error(
        `no UTXOs available for address ${senderAddress}. Fund the wallet first.`
      );
    }

    const totalBalance = (entries as Array<{ amount: bigint }>).reduce(
      (sum, e) => sum + e.amount,
      0n
    );
    if (totalBalance < amountSompi + priorityFeeSompi) {
      throw new Error(
        `insufficient balance: have ${sompiToKaspaString(totalBalance)} KAS, ` +
          `need at least ${sompiToKaspaString(amountSompi)} KAS + fees`
      );
    }

    // Sort UTXOs smallest first for efficient consolidation.
    (entries as Array<{ amount: bigint }>).sort((a, b) =>
      a.amount > b.amount ? 1 : -1
    );

    return { rpc, entries: entries as Array<{ amount: bigint }>, senderAddress };
  } catch (err) {
    // Failed before we hand the rpc back to the caller — clean up here.
    try { await rpc.disconnect(); } catch { /* noop */ }
    throw err;
  }
}

function buildGenerator(
  to: string,
  amountSompi: bigint,
  priorityFeeSompi: bigint,
  payload: string | undefined,
  entries: unknown,
  senderAddress: string,
  networkId: string
): kaspa.Generator {
  return new Generator({
    entries: entries as never,
    outputs: [{ address: to, amount: amountSompi }],
    priorityFee: priorityFeeSompi,
    changeAddress: senderAddress,
    networkId,
    ...(payload ? { payload: hexToBytes(payload) } : {}),
  });
}

// ── Public: buildPreview ──────────────────────────────────────────────

export async function buildPreview(args: {
  to: string;
  amountSompi: bigint;
  priorityFeeSompi: bigint;
  payload?: string;
}): Promise<BuildPreview> {
  const { to, amountSompi, priorityFeeSompi, payload } = args;

  // Validate before any RPC. Phase 3 will call buildPreview directly, so
  // the cap, minimum-output rules, and recipient checksum/prefix must live
  // here, not just at the tool handler.
  checkAmounts(amountSompi, priorityFeeSompi);
  checkPayload(payload);

  const wallet = getWallet();
  const networkId = wallet.getNetworkId();
  checkRecipient(to, networkId);

  if (TX_MOCK) {
    // Canned preview that round-trips through the same TxParams shape so
    // signAndSubmit (also mocked) sees a faithful bundle.
    const params: TxParams = {
      to,
      amountSompi: amountSompi.toString(),
      priorityFeeSompi: priorityFeeSompi.toString(),
      ...(payload ? { payload } : {}),
      network: networkId,
      senderAddress: wallet.getAddress(),
    };
    return {
      previewText:
        `[MOCK] network: ${networkId}\n[MOCK] to: ${to}\n` +
        `[MOCK] amount: ${amountSompi} sompi\n[MOCK] fee: 1234 sompi`,
      feeSompi: "1234",
      totalTransactions: 1,
      params,
    };
  }

  const ctx = await preflight(to, amountSompi, priorityFeeSompi);
  try {
    // Use the WASM SDK's purpose-built estimator — it returns a
    // GeneratorSummary without producing PendingTransaction handles, which
    // is exactly the shape we want for preview (no WASM objects need to
    // outlive this call).
    const summary = await estimateTransactions({
      entries: ctx.entries as never,
      outputs: [{ address: to, amount: amountSompi }],
      priorityFee: priorityFeeSompi,
      changeAddress: ctx.senderAddress,
      networkId,
      ...(payload ? { payload: hexToBytes(payload) } : {}),
    });

    const feeSompi = BigInt(summary.fees);
    const total = Number(summary.transactions);
    if (total === 0) {
      throw new Error("transaction generation failed: no transactions produced");
    }

    const params: TxParams = {
      to,
      amountSompi: amountSompi.toString(),
      priorityFeeSompi: priorityFeeSompi.toString(),
      ...(payload ? { payload } : {}),
      network: networkId,
      senderAddress: ctx.senderAddress,
    };

    const previewText =
      `network: ${networkId}\n` +
      `from:    ${ctx.senderAddress}\n` +
      `to:      ${to}\n` +
      `amount:  ${sompiToKaspaString(amountSompi)} KAS (${amountSompi} sompi)\n` +
      `fee:     ~${sompiToKaspaString(feeSompi)} KAS (${feeSompi} sompi)\n` +
      `chunks:  ${total} tx(s)` +
      (payload ? `\npayload: ${payload.length / 2} bytes` : "");

    return {
      previewText,
      feeSompi: feeSompi.toString(),
      totalTransactions: total,
      params,
    };
  } finally {
    try { await ctx.rpc.disconnect(); } catch { /* noop */ }
  }
}

// ── Public: signAndSubmit ─────────────────────────────────────────────

export async function signAndSubmit(params: TxParams): Promise<SubmitResult> {
  // Validate the params bundle before anything else. The pending-tx map
  // (Phase 3) will only ever contain server-generated params, but
  // signAndSubmit is the signing boundary — defend it as if any caller
  // could feed it arbitrary input. Every string field is type-checked
  // explicitly; the regex/checksum validators rely on the assertion.
  if (params === null || typeof params !== "object") {
    throw new Error(`params must be an object (got ${typeof params})`);
  }
  assertString("params.network", params.network);
  assertString("params.senderAddress", params.senderAddress);

  const amountSompi = parseSompiField("amountSompi", params.amountSompi);
  const priorityFeeSompi = parseSompiField(
    "priorityFeeSompi",
    params.priorityFeeSompi
  );
  checkAmounts(amountSompi, priorityFeeSompi);
  checkPayload(params.payload);
  // Recipient checksum is verified against params.network (not the wallet's
  // current network) so the validation is consistent with the params bundle
  // even before drift guards have a chance to run.
  checkRecipient(params.to, params.network);

  const wallet = getWallet();

  if (TX_MOCK) {
    // Same drift checks as the real path so test coverage stays honest;
    // bypass only the RPC-bound work.
    if (wallet.getNetworkId() !== params.network) {
      throw new Error(
        `wallet network changed since preview: was "${params.network}", ` +
          `now "${wallet.getNetworkId()}"`
      );
    }
    if (wallet.getAddress() !== params.senderAddress) {
      throw new Error(
        `wallet sender address changed since preview: was "${params.senderAddress}", ` +
          `now "${wallet.getAddress()}"`
      );
    }
    return {
      txId: "0xmocktx" + Math.floor(Math.random() * 1e9).toString(16),
      fee: "0.00001234",
      totalTransactions: 1,
    };
  }

  // Network drift guard: if the active wallet's network changed between
  // preview and submit (kaspa_load_wallet was called), refuse rather than
  // sending to the wrong network's address.
  if (wallet.getNetworkId() !== params.network) {
    throw new Error(
      `wallet network changed since preview: was "${params.network}", ` +
        `now "${wallet.getNetworkId()}"`
    );
  }
  if (wallet.getAddress() !== params.senderAddress) {
    throw new Error(
      `wallet sender address changed since preview: was "${params.senderAddress}", ` +
        `now "${wallet.getAddress()}"`
    );
  }

  // Re-fetch UTXOs fresh. We deliberately do not reuse anything from the
  // preview step — the preview is a state-machine handle, not a snapshot.
  const ctx = await preflight(params.to, amountSompi, priorityFeeSompi);

  const submittedTxIds: string[] = [];
  try {
    const generator = buildGenerator(
      params.to,
      amountSompi,
      priorityFeeSompi,
      params.payload,
      ctx.entries,
      ctx.senderAddress,
      params.network
    );

    let pending: kaspa.PendingTransaction | undefined;
    let lastTxId = "";
    while ((pending = await generator.next())) {
      await pending.sign([wallet.getPrivateKey()]);
      const txId = await pending.submit(ctx.rpc);
      submittedTxIds.push(txId);
      lastTxId = txId;
    }
    if (!lastTxId) {
      throw new Error("transaction generation failed: no transactions produced");
    }

    const summary = generator.summary();
    return {
      txId: lastTxId,
      fee: sompiToKaspaString(summary.fees).toString(),
      totalTransactions: submittedTxIds.length,
    };
  } catch (error) {
    if (submittedTxIds.length > 0) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(
        `transaction partially completed. ${submittedTxIds.length} tx(s) broadcast: ` +
          `[${submittedTxIds.join(", ")}]. Error: ${detail}`
      );
    }
    throw error;
  } finally {
    try { await ctx.rpc.disconnect(); } catch { /* noop */ }
  }
}

// ── Compat shim: old single-shot sendKaspa ────────────────────────────

/**
 * Build → submit in one call. Preserved so existing callers in wallet-tools
 * keep working through Phase 4.5; Phase 3 will replace the call site with
 * the two-step preview/confirm flow that uses buildPreview + signAndSubmit
 * directly.
 */
export async function sendKaspa(
  to: string,
  amountSompi: bigint,
  priorityFeeSompi: bigint = 0n,
  payload?: string
): Promise<SubmitResult> {
  const preview = await buildPreview({
    to,
    amountSompi,
    priorityFeeSompi,
    ...(payload ? { payload } : {}),
  });
  return signAndSubmit(preview.params);
}
