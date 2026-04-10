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
  setWalletInstance,
  KaspaWallet,
  type NetworkTypeName,
} from "../services/wallet.js";
import { sendKaspa } from "../services/transaction.js";
import {
  saveEncryptedWallet,
  loadEncryptedWallet,
  walletFileExists,
  getWalletFilePath,
} from "../services/wallet-store.js";

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
      description: `Get the Kaspa address derived from the active wallet.

Requires an active wallet — use kaspa_load_wallet to unlock a saved wallet, kaspa_generate_mnemonic to create one, or set KASPA_MNEMONIC/KASPA_PRIVATE_KEY env var.

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
          ? "Encrypted wallet found. Use kaspa_load_wallet to unlock."
          : "Use kaspa_generate_mnemonic to create a wallet, or set KASPA_MNEMONIC env var.";
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

  // ── Send Transaction ────────────────────────────────────────────────

  server.registerTool(
    "kaspa_send_transaction",
    {
      title: "Send KAS Transaction",
      description: `Build, sign, and submit a Kaspa transaction to send KAS to a recipient address.

Uses the WASM Generator for KIP-9 compliant UTXO management. Connects to the node's Borsh endpoint (KASPA_BORSH_ENDPOINT, default ws://127.0.0.1:17210) for UTXO fetching and submission.

Requires an active wallet — use kaspa_load_wallet, kaspa_generate_mnemonic, or KASPA_MNEMONIC env var.

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
        const hint = walletFileExists()
          ? "Encrypted wallet found. Use kaspa_load_wallet to unlock."
          : "Use kaspa_generate_mnemonic to create a wallet, or set KASPA_MNEMONIC env var.";
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
      description: `Generate a new BIP39 mnemonic phrase and derive the corresponding Kaspa wallet address. The wallet is auto-activated for this session.

Use kaspa_save_wallet to encrypt and persist it for future sessions.

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
      setWalletInstance(wallet);

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
                  "IMPORTANT: Save this mnemonic securely — it cannot be recovered if lost. Use kaspa_save_wallet to encrypt and store it for future sessions.",
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

  // ── Save Wallet (Encrypted) ──────────────────────────────────────────

  server.registerTool(
    "kaspa_save_wallet",
    {
      title: "Save Wallet (Encrypted)",
      description: `Encrypt the active wallet's mnemonic with AES-256-GCM and save to ~/.kaspa-mcp/wallet.enc (chmod 600).

Key derivation: scrypt (N=65536, r=8, p=1). Overwrites any existing wallet file.

Requires an active wallet with a mnemonic (from kaspa_generate_mnemonic or KASPA_MNEMONIC env var). Wallets loaded from a raw private key cannot be saved.

Next session, use kaspa_load_wallet to decrypt and activate.`,
      inputSchema: {
        password: z
          .string()
          .min(1)
          .describe("Password to encrypt the wallet file"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ password }) => {
      try {
        if (!isWalletConfigured()) {
          throw new Error(
            "No active wallet. Use kaspa_generate_mnemonic to create one first."
          );
        }

        const wallet = getWallet();
        const mnemonic = wallet.getMnemonic();
        if (!mnemonic) {
          throw new Error(
            "Cannot save: wallet was loaded from a private key, not a mnemonic. " +
              "Only mnemonic-based wallets can be saved."
          );
        }

        saveEncryptedWallet(
          mnemonic,
          password,
          wallet.getNetworkId(),
          wallet.getAccountIndex()
        );

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  success: true,
                  path: getWalletFilePath(),
                  network: wallet.getNetworkId(),
                  address: wallet.getAddress(),
                  message:
                    "Wallet encrypted and saved. Use kaspa_load_wallet to unlock in future sessions.",
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

  // ── Load Wallet (Decrypt) ────────────────────────────────────────────

  server.registerTool(
    "kaspa_load_wallet",
    {
      title: "Load Wallet (Decrypt)",
      description: `Decrypt the wallet file at ~/.kaspa-mcp/wallet.enc and activate it for this session.

After loading, all wallet tools (kaspa_get_my_address, kaspa_send_transaction, etc.) are ready to use.

The wallet file must have been previously created with kaspa_save_wallet.`,
      inputSchema: {
        password: z
          .string()
          .min(1)
          .describe("Password used when the wallet was saved"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ password }) => {
      try {
        const { mnemonic, network, accountIndex } =
          loadEncryptedWallet(password);
        const wallet = KaspaWallet.fromMnemonic(
          mnemonic,
          network as NetworkTypeName,
          accountIndex
        );
        setWalletInstance(wallet);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  success: true,
                  address: wallet.getAddress(),
                  network: wallet.getNetworkId(),
                  message: "Wallet unlocked and ready.",
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
}
