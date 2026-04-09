/**
 * Wallet and transaction MCP tools.
 *
 * These tools require KASPA_MNEMONIC or KASPA_PRIVATE_KEY to be configured.
 * They provide wallet address derivation, transaction sending, fee estimation,
 * and mnemonic generation.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as kaspa from "kaspa-wasm";
import { KaspaWrpcClient } from "../services/kaspa-client.js";
import {
  getWallet,
  isWalletConfigured,
  KaspaWallet,
  type NetworkTypeName,
} from "../services/wallet.js";
import { sendKaspa } from "../services/transaction.js";

const { Mnemonic, Address, NetworkType } = kaspa;

const SOMPI_PER_KAS = 100_000_000n;
const MAX_DECIMAL_PLACES = 8;

function kasToSompi(amountStr: string): bigint {
  const trimmed = amountStr.trim();
  if (!/^\d+(\.\d+)?$/.test(trimmed)) {
    throw new Error("Amount must be a valid decimal number");
  }

  const parts = trimmed.split(".");
  const integerPart = parts[0];
  let fractionalPart = parts[1] || "";

  if (fractionalPart.length > MAX_DECIMAL_PLACES) {
    throw new Error(
      `Amount cannot have more than ${MAX_DECIMAL_PLACES} decimal places`
    );
  }

  fractionalPart = fractionalPart.padEnd(MAX_DECIMAL_PLACES, "0");
  const sompi = BigInt(integerPart) * SOMPI_PER_KAS + BigInt(fractionalPart);

  if (sompi <= 0n) {
    throw new Error("Amount must be greater than zero");
  }

  return sompi;
}

function validateAddress(address: string): void {
  let parsed: kaspa.Address;
  try {
    parsed = new Address(address);
  } catch {
    throw new Error(`Invalid Kaspa address: ${address}`);
  }

  const wallet = getWallet();
  const walletNetwork = wallet.getNetworkType();
  const expectedPrefix =
    walletNetwork === NetworkType.Mainnet ? "kaspa" : "kaspatest";

  if (parsed.prefix !== expectedPrefix) {
    throw new Error(
      `Address network mismatch: wallet is on ${wallet.getNetworkId()}, ` +
        `but address prefix "${parsed.prefix}" does not match expected "${expectedPrefix}"`
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
      description: `Get the Kaspa address derived from the configured wallet (mnemonic or private key).

Requires KASPA_MNEMONIC or KASPA_PRIVATE_KEY environment variable.

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
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  error:
                    "Wallet not configured. Set KASPA_MNEMONIC or KASPA_PRIVATE_KEY environment variable.",
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

  // ── Send Transaction ────────────────────────────────────────────────

  server.registerTool(
    "kaspa_send_transaction",
    {
      title: "Send KAS Transaction",
      description: `Build, sign, and submit a Kaspa transaction to send KAS to a recipient address.

Uses the WASM Generator for KIP-9 compliant UTXO management. Connects to the node's Borsh endpoint (KASPA_BORSH_ENDPOINT, default ws://127.0.0.1:17210) for UTXO fetching and submission.

Requires KASPA_MNEMONIC or KASPA_PRIVATE_KEY environment variable.

Args:
  - to: recipient Kaspa address
  - amount: amount to send in KAS (e.g. "1.5" or "100")
  - priorityFee: optional priority fee in sompi (default: 0)
  - payload: optional hex-encoded transaction payload

Returns:
  - txId: the submitted transaction ID
  - fee: total fees paid in KAS
  - totalTransactions: number of transactions submitted (may be >1 for large UTXO sets)`,
      inputSchema: {
        to: z
          .string()
          .min(10)
          .describe("Recipient Kaspa address (kaspa: or kaspatest: prefix)"),
        amount: z
          .string()
          .describe("Amount to send in KAS (e.g. '1.5', '100', '0.001')"),
        priorityFee: z
          .number()
          .int()
          .min(0)
          .optional()
          .describe("Priority fee in sompi (optional, default: 0)"),
        payload: z
          .string()
          .regex(/^[0-9a-fA-F]*$/, "Payload must be hex-encoded")
          .optional()
          .describe("Hex-encoded transaction payload (optional)"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ to, amount, priorityFee, payload }) => {
      if (!isWalletConfigured()) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  error:
                    "Wallet not configured. Set KASPA_MNEMONIC or KASPA_PRIVATE_KEY environment variable.",
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        };
      }

      try {
        validateAddress(to);
        const amountSompi = kasToSompi(amount);

        const result = await sendKaspa(
          to,
          amountSompi,
          BigInt(priorityFee || 0),
          payload
        );

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  success: true,
                  txId: result.txId,
                  fee: result.fee,
                  totalTransactions: result.totalTransactions,
                  to,
                  amount,
                  senderAddress: getWallet().getAddress(),
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        const message =
          error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ error: message }, null, 2),
            },
          ],
          isError: true,
        };
      }
    }
  );

  // ── Generate Mnemonic ───────────────────────────────────────────────

  server.registerTool(
    "kaspa_generate_mnemonic",
    {
      title: "Generate New Mnemonic",
      description: `Generate a new BIP39 mnemonic phrase and derive the corresponding Kaspa wallet address. Use this to create a new wallet.

The generated mnemonic can then be set as KASPA_MNEMONIC to use with this MCP server.

Args:
  - wordCount: 12 or 24 words (default: 24)
  - network: network for address derivation (default: testnet-12)

Returns:
  - mnemonic: the generated mnemonic phrase
  - address: the derived Kaspa address
  - network: which network was used
  - warning: security reminder`,
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
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async ({ wordCount, network }) => {
      const words = wordCount ?? 24;
      const net = (network ?? "testnet-12") as NetworkTypeName;

      const mnemonic = Mnemonic.random(words);
      const phrase = mnemonic.phrase;
      const wallet = KaspaWallet.fromMnemonic(phrase, net, 0);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                mnemonic: phrase,
                address: wallet.getAddress(),
                network: net,
                warning:
                  "IMPORTANT: Save this mnemonic securely. It cannot be recovered if lost. Never share it with anyone.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

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
}
