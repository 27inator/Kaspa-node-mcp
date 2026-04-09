/**
 * Transaction building and submission module.
 *
 * Uses kaspa-wasm Generator for KIP-9 compliant transaction creation.
 * Connects to the node's Borsh wRPC endpoint via the WASM RpcClient
 * for UTXO fetching and transaction submission.
 */

import * as kaspa from "kaspa-wasm";
import { getWallet } from "./wallet.js";

const { Generator, RpcClient, Encoding, sompiToKaspaString, Address } = kaspa;

export interface SendResult {
  txId: string;
  fee: string;
  totalTransactions: number;
}

const CONNECT_TIMEOUT_MS = 30_000;

function getBorshEndpoint(): string {
  return process.env.KASPA_BORSH_ENDPOINT ?? "ws://127.0.0.1:17210";
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
 * Create an ephemeral WASM RpcClient connected to the local node's Borsh endpoint.
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

/**
 * Build, sign, and submit a Kaspa transaction.
 *
 * Uses the WASM Generator for KIP-9 compliant UTXO management.
 * May produce multiple chained transactions for large UTXO sets.
 */
export async function sendKaspa(
  to: string,
  amountSompi: bigint,
  priorityFee: bigint = 0n,
  payload?: string
): Promise<SendResult> {
  const wallet = getWallet();
  const senderAddress = wallet.getAddress();
  const rpc = await createRpcClient();
  const submittedTxIds: string[] = [];

  try {
    const { isSynced } = await rpc.getServerInfo();
    if (!isSynced) {
      throw new Error("Node is not synced — cannot submit transactions");
    }

    // Fetch UTXOs via WASM RPC (returns correctly typed UtxoEntry objects)
    const { entries } = await rpc.getUtxosByAddresses([
      new Address(senderAddress),
    ]);

    if (!entries || entries.length === 0) {
      throw new Error(
        `No UTXOs available for address ${senderAddress}. Fund the wallet first.`
      );
    }

    // Check balance
    const totalBalance = entries.reduce(
      (sum: bigint, e: { amount: bigint }) => sum + e.amount,
      0n
    );
    if (totalBalance < amountSompi + priorityFee) {
      throw new Error(
        `Insufficient balance: have ${sompiToKaspaString(totalBalance)} KAS, ` +
          `need at least ${sompiToKaspaString(amountSompi)} KAS + fees`
      );
    }

    // TN12+ uses 3-dimensional mass (compute, storage, transient).
    // Storage mass = C / output_value, so tiny outputs are extremely heavy.
    // Reject amounts below 0.1 KAS (10_000_000 sompi) to avoid
    // "Storage mass exceeds maximum" errors from the Generator.
    const MIN_OUTPUT_SOMPI = 10_000_000n; // 0.1 KAS
    if (amountSompi < MIN_OUTPUT_SOMPI) {
      throw new Error(
        `Amount too small: minimum is 0.1 KAS (${MIN_OUTPUT_SOMPI} sompi) ` +
          `due to TN12 storage mass rules`
      );
    }

    // Sort UTXOs smallest first for efficient consolidation
    entries.sort((a: { amount: bigint }, b: { amount: bigint }) =>
      a.amount > b.amount ? 1 : -1
    );

    // Build transaction(s) with WASM Generator
    const generator = new Generator({
      entries,
      outputs: [{ address: to, amount: amountSompi }],
      priorityFee,
      changeAddress: senderAddress,
      networkId: wallet.getNetworkId(),
      ...(payload ? { payload: hexToBytes(payload) } : {}),
    });

    let pending: kaspa.PendingTransaction | undefined;
    let lastTxId = "";

    while ((pending = await generator.next())) {
      await pending.sign([wallet.getPrivateKey()]);
      const txId = await pending.submit(rpc);
      submittedTxIds.push(txId);
      lastTxId = txId;
    }

    if (!lastTxId) {
      throw new Error("Transaction generation failed: no transactions produced");
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
        `Transaction partially completed. ${submittedTxIds.length} tx(s) broadcast: ` +
          `[${submittedTxIds.join(", ")}]. Error: ${detail}`
      );
    }
    throw error;
  } finally {
    try {
      await rpc.disconnect();
    } catch {
      // Disconnect failure is not actionable
    }
  }
}
