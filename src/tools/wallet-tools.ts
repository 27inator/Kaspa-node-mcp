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
  activateWallet,
  KaspaWallet,
  type NetworkTypeName,
} from "../services/wallet.js";
import { sendKaspa } from "../services/transaction.js";
import {
  saveEncryptedWallet,
  loadEncryptedWallet,
  hasSavedWallet,
  getWalletFilePath,
} from "../services/wallet-storage.js";

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
      description: `Generate a new BIP39 mnemonic phrase, derive the corresponding Kaspa wallet address, and activate it immediately for this session.

The wallet is ready to use right away. Use kaspa_save_wallet to encrypt and persist it for future sessions.

Args:
  - wordCount: 12 or 24 words (default: 24)
  - network: network for address derivation (default: testnet-12)

Returns:
  - mnemonic: the generated mnemonic phrase
  - address: the derived Kaspa address
  - network: which network was used
  - activated: whether the wallet was activated for this session
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

      if (isWalletConfigured()) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  error:
                    "A wallet is already active. Generating a new mnemonic would overwrite it. " +
                    "If you want a new wallet, restart the MCP server without KASPA_MNEMONIC/KASPA_PRIVATE_KEY set.",
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        };
      }

      const mnemonic = Mnemonic.random(words);
      const phrase = mnemonic.phrase;

      // Auto-activate the wallet for this session
      const wallet = activateWallet(phrase, net, 0);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                mnemonic: phrase,
                address: wallet.getAddress(),
                network: net,
                activated: true,
                warning:
                  "IMPORTANT: This wallet is now active for this session. " +
                  "Use kaspa_save_wallet to encrypt and persist it for future sessions. " +
                  "The mnemonic cannot be recovered if lost. Never share it with anyone.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // ── Save Wallet ─────────────────────────────────────────────────────

  server.registerTool(
    "kaspa_save_wallet",
    {
      title: "Save Wallet (Encrypted)",
      description: `Encrypt the currently active wallet with a password and save it to disk (~/.kaspa-mcp/wallet.enc).

Uses AES-256-GCM encryption with scrypt key derivation. The file is created with owner-only permissions (0600).

A wallet must be active (either via kaspa_generate_mnemonic, kaspa_load_wallet, or environment variables).

Args:
  - password: password to encrypt the wallet with (choose a strong one)

Returns:
  - path: where the encrypted wallet was saved
  - network: which network the wallet is configured for
  - address: the wallet address`,
      inputSchema: {
        password: z
          .string()
          .min(8, "Password must be at least 8 characters")
          .describe("Password to encrypt the wallet (min 8 characters)"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ password }) => {
      if (!isWalletConfigured()) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  error:
                    "No wallet is active. Generate one first with kaspa_generate_mnemonic or load one with kaspa_load_wallet.",
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        };
      }

      const mnemonic = process.env.KASPA_MNEMONIC;
      if (!mnemonic) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  error:
                    "Wallet was configured via private key, not mnemonic. Only mnemonic-based wallets can be saved.",
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
        const wallet = getWallet();
        const network = process.env.KASPA_NETWORK || "testnet-12";
        const accountIndex = parseInt(process.env.KASPA_ACCOUNT_INDEX || "0", 10);

        const filePath = saveEncryptedWallet(
          { mnemonic, network, accountIndex },
          password
        );

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  saved: true,
                  path: filePath,
                  address: wallet.getAddress(),
                  network,
                  hint: "Use kaspa_load_wallet with the same password to restore this wallet in future sessions.",
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
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

  // ── Load Wallet ─────────────────────────────────────────────────────

  server.registerTool(
    "kaspa_load_wallet",
    {
      title: "Load Wallet (Encrypted)",
      description: `Decrypt and activate a previously saved wallet from ~/.kaspa-mcp/wallet.enc.

Requires the same password used when saving with kaspa_save_wallet.

Args:
  - password: the password used to encrypt the wallet

Returns:
  - address: the restored wallet address
  - network: which network the wallet is configured for`,
      inputSchema: {
        password: z
          .string()
          .min(1)
          .describe("Password to decrypt the wallet"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ password }) => {
      if (isWalletConfigured()) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  error:
                    "A wallet is already active. Restart the MCP server without KASPA_MNEMONIC/KASPA_PRIVATE_KEY to load a saved wallet.",
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
        const data = loadEncryptedWallet(password);
        const wallet = activateWallet(
          data.mnemonic,
          data.network as NetworkTypeName,
          data.accountIndex
        );

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  loaded: true,
                  address: wallet.getAddress(),
                  network: data.network,
                  hint: "Wallet is now active. You can use kaspa_get_my_address, kaspa_send_transaction, etc.",
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
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
