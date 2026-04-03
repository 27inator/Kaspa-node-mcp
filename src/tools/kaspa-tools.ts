/**
 * Kaspa Node MCP tools.
 *
 * All tools are read-only. This MCP server never submits transactions
 * or modifies node state. It's designed for verification and monitoring.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { KaspaWrpcClient } from "../services/kaspa-client.js";
import { parseKpmPayload } from "../services/kpm-payload.js";
import type {
  GetInfoResponse,
  GetServerInfoResponse,
  GetBlockDagInfoResponse,
  GetBlockResponse,
  GetUtxosByAddressesResponse,
  GetBalanceByAddressResponse,
  GetCoinSupplyResponse,
  Block,
  Transaction,
} from "../types.js";
import { sompiToKas } from "../types.js";

export function registerTools(server: McpServer, client: KaspaWrpcClient): void {

  // ── Node Health ────────────────────────────────────────────────────

  server.registerTool(
    "kaspa_get_info",
    {
      title: "Get Kaspa Node Info",
      description: `Get basic information about the connected Kaspa node including sync status, UTXO index availability, mempool size, server version, and P2P identifier. Use this as a health check to confirm the node is reachable and synced.

Returns:
  - isSynced: whether the node is fully synced with the network
  - isUtxoIndexed: whether UTXO index is enabled (required for balance/UTXO queries)
  - mempoolSize: number of transactions in mempool
  - serverVersion: rusty-kaspa version string
  - p2pId: unique node identifier`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async () => {
      const data = (await client.request("getInfo")) as unknown as GetInfoResponse;
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(data, null, 2),
        }],
      };
    }
  );

  server.registerTool(
    "kaspa_get_server_info",
    {
      title: "Get Kaspa Server Info",
      description: `Get detailed server information including network ID (mainnet/testnet-10/testnet-11/devnet), RPC API version, current virtual DAA score, and UTXO index status.

Returns:
  - networkId: which Kaspa network this node is on
  - serverVersion: rusty-kaspa version
  - virtualDaaScore: current DAA score (block height equivalent)
  - isSynced: sync status
  - rpcApiVersion/rpcApiRevision: API compatibility info`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async () => {
      const data = (await client.request("getServerInfo")) as unknown as GetServerInfoResponse;
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(data, null, 2),
        }],
      };
    }
  );

  // ── Chain State ────────────────────────────────────────────────────

  server.registerTool(
    "kaspa_get_block_dag_info",
    {
      title: "Get Block DAG Info",
      description: `Get current state of the Kaspa block DAG including block count, difficulty, tip hashes, virtual DAA score, pruning point, and network name. Use this to understand the current chain state and verify confirmation depth.

Returns:
  - blockCount: total blocks in the DAG
  - difficulty: current mining difficulty
  - network: network name (e.g. "testnet-10")
  - tipHashes: current DAG tip block hashes
  - virtualDaaScore: current DAA score
  - virtualParentHashes: virtual block's parent hashes
  - pruningPointHash: current pruning point
  - sink: the DAG sink hash`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async () => {
      const data = (await client.request("getBlockDagInfo")) as unknown as GetBlockDagInfoResponse;
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(data, null, 2),
        }],
      };
    }
  );

  server.registerTool(
    "kaspa_get_block",
    {
      title: "Get Block by Hash",
      description: `Fetch a specific block by its hash, optionally including full transaction data. Use this to verify that a KPM anchor transaction landed in a specific block, or to inspect block structure.

Args:
  - hash: block hash (64-char hex string)
  - includeTransactions: whether to include full transaction objects (default: false, returns only transaction IDs in verboseData)

Returns:
  - block.header: block header with daaScore, timestamp, parentsByLevel, merkle roots
  - block.verboseData: includes transactionIds, isChainBlock, selectedParentHash, mergeSetBlues/Reds
  - block.transactions: full transaction objects (only if includeTransactions=true)`,
      inputSchema: {
        hash: z.string()
          .length(64, "Block hash must be exactly 64 hex characters")
          .regex(/^[0-9a-f]+$/, "Block hash must be lowercase hex")
          .describe("Block hash (64-char lowercase hex)"),
        includeTransactions: z.boolean()
          .default(false)
          .describe("Include full transaction data (can be large)"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ hash, includeTransactions }) => {
      const data = (await client.request("getBlock", {
        hash,
        includeTransactions,
      })) as unknown as GetBlockResponse;
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(data, null, 2),
        }],
      };
    }
  );

  // ── Wallet / UTXO ─────────────────────────────────────────────────

  server.registerTool(
    "kaspa_get_balance",
    {
      title: "Get Balance by Address",
      description: `Get the balance of a Kaspa address in both sompi and KAS. Requires UTXO index to be enabled on the node.

Args:
  - address: Kaspa address (e.g. "kaspatest:qq..." for testnet, "kaspa:qq..." for mainnet)

Returns:
  - balance: balance in sompi (1 KAS = 100,000,000 sompi)
  - balanceKas: balance formatted in KAS`,
      inputSchema: {
        address: z.string()
          .min(10, "Address too short")
          .describe("Kaspa address (kaspa: or kaspatest: prefix)"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ address }) => {
      // Some node versions return empty for getBalanceByAddress,
      // so we fall back to summing UTXOs
      try {
        const data = (await client.request("getBalanceByAddress", {
          address,
        })) as unknown as GetBalanceByAddressResponse;

        if (data.balance !== undefined) {
          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                address,
                balance: data.balance,
                balanceKas: sompiToKas(data.balance),
              }, null, 2),
            }],
          };
        }
      } catch {
        // Fall through to UTXO sum
      }

      // Fallback: sum UTXOs
      const utxoData = (await client.request("getUtxosByAddresses", {
        addresses: [address],
      })) as unknown as GetUtxosByAddressesResponse;

      const totalSompi = (utxoData.entries ?? []).reduce(
        (sum, entry) => sum + entry.utxoEntry.amount,
        0
      );

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            address,
            balance: totalSompi,
            balanceKas: sompiToKas(totalSompi),
            utxoCount: utxoData.entries?.length ?? 0,
            source: "utxo_sum",
          }, null, 2),
        }],
      };
    }
  );

  server.registerTool(
    "kaspa_get_utxos",
    {
      title: "Get UTXOs by Address",
      description: `Get the unspent transaction outputs (UTXOs) for one or more Kaspa addresses. Use this to check UTXO fragmentation, verify wallet state, or find specific transaction references.

Args:
  - addresses: array of Kaspa addresses to query

Returns:
  Array of UTXO entries, each containing:
  - address: the owning address
  - outpoint.transactionId: the transaction that created this UTXO
  - outpoint.index: output index within that transaction
  - utxoEntry.amount: value in sompi
  - utxoEntry.blockDaaScore: DAA score of the block containing this UTXO
  - utxoEntry.isCoinbase: whether this is a coinbase output`,
      inputSchema: {
        addresses: z.array(z.string().min(10))
          .min(1, "At least one address required")
          .max(100, "Maximum 100 addresses per query")
          .describe("Array of Kaspa addresses"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ addresses }) => {
      const data = (await client.request("getUtxosByAddresses", {
        addresses,
      })) as unknown as GetUtxosByAddressesResponse;

      const totalSompi = (data.entries ?? []).reduce(
        (sum, entry) => sum + entry.utxoEntry.amount,
        0
      );

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            totalUtxos: data.entries?.length ?? 0,
            totalBalance: totalSompi,
            totalBalanceKas: sompiToKas(totalSompi),
            entries: data.entries ?? [],
          }, null, 2),
        }],
      };
    }
  );

  // ── Transaction Verification ───────────────────────────────────────

  server.registerTool(
    "kaspa_find_transaction_in_block",
    {
      title: "Find Transaction in Block",
      description: `Fetch a block with full transactions and search for a specific transaction by ID. Use this to verify that a KPM anchor transaction exists in a specific block and to extract its payload.

If the transaction contains a KPM anchor payload (starts with "KPM1" magic bytes), the payload is automatically parsed to show the anchor mode (INDIVIDUAL/MERKLE) and the 32-byte hash (event hash or merkle root).

Args:
  - blockHash: the block hash to search in (64-char hex)
  - transactionId: the transaction ID to find (64-char hex)

Returns:
  - found: whether the transaction was found in this block
  - transaction: full transaction object if found
  - kpmPayload: parsed KPM anchor data if the transaction contains a KPM payload`,
      inputSchema: {
        blockHash: z.string()
          .length(64, "Block hash must be 64 hex chars")
          .regex(/^[0-9a-f]+$/, "Must be lowercase hex")
          .describe("Block hash to search in"),
        transactionId: z.string()
          .length(64, "Transaction ID must be 64 hex chars")
          .regex(/^[0-9a-f]+$/, "Must be lowercase hex")
          .describe("Transaction ID to find"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ blockHash, transactionId }) => {
      const data = (await client.request("getBlock", {
        hash: blockHash,
        includeTransactions: true,
      })) as unknown as GetBlockResponse;

      // Check transaction IDs in verbose data first (faster)
      const txIds = data.block.verboseData?.transactionIds ?? [];
      if (!txIds.includes(transactionId)) {
        // Also check full transactions if loaded
        const foundInTxs = data.block.transactions?.find(
          (tx) => tx.verboseData?.transactionId === transactionId
        );

        if (!foundInTxs) {
          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                found: false,
                blockHash,
                transactionId,
                message: `Transaction not found in block. Block contains ${txIds.length} transaction(s).`,
                blockTransactionIds: txIds,
              }, null, 2),
            }],
          };
        }
      }

      // Find the full transaction
      const tx = data.block.transactions?.find(
        (t) => t.verboseData?.transactionId === transactionId
      );

      const result: Record<string, unknown> = {
        found: true,
        blockHash,
        transactionId,
        blockDaaScore: data.block.header.daaScore,
        blockTimestamp: data.block.header.timestamp,
        isChainBlock: data.block.verboseData?.isChainBlock,
      };

      if (tx) {
        result.transaction = tx;
        // Try to parse KPM payload
        if (tx.payload) {
          result.kpmPayload = parseKpmPayload(tx.payload);
        }
      } else {
        result.message = "Transaction ID found in block's transaction list but full transaction data not available. Try fetching the block with includeTransactions=true.";
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        }],
      };
    }
  );

  server.registerTool(
    "kaspa_search_blocks_for_transaction",
    {
      title: "Search Recent Blocks for Transaction",
      description: `Search through recent blocks to find which block contains a specific transaction. This is useful when you have a transaction ID (e.g. from KPM's kaspa_txid) but don't know which block it's in.

Searches backwards from the current DAG tips, checking up to maxBlocks blocks.

Args:
  - transactionId: the transaction ID to search for (64-char hex)
  - maxBlocks: maximum number of blocks to search (default: 50, max: 200)

Returns:
  - found: whether the transaction was located
  - blockHash: the block containing the transaction (if found)
  - blockDaaScore: DAA score of that block
  - kpmPayload: parsed KPM payload if present`,
      inputSchema: {
        transactionId: z.string()
          .length(64, "Transaction ID must be 64 hex chars")
          .regex(/^[0-9a-f]+$/, "Must be lowercase hex")
          .describe("Transaction ID to search for"),
        maxBlocks: z.number()
          .int()
          .min(1)
          .max(200)
          .default(50)
          .describe("Maximum blocks to search (default: 50)"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ transactionId, maxBlocks }) => {
      // Get current tips
      const dagInfo = (await client.request("getBlockDagInfo")) as unknown as GetBlockDagInfoResponse;

      const visited = new Set<string>();
      const queue = [...dagInfo.tipHashes];
      let blocksChecked = 0;

      while (queue.length > 0 && blocksChecked < maxBlocks) {
        const hash = queue.shift()!;
        if (visited.has(hash)) continue;
        visited.add(hash);
        blocksChecked++;

        try {
          const blockData = (await client.request("getBlock", {
            hash,
            includeTransactions: true,
          })) as unknown as GetBlockResponse;

          const txIds = blockData.block.verboseData?.transactionIds ?? [];
          if (txIds.includes(transactionId)) {
            const tx = blockData.block.transactions?.find(
              (t) => t.verboseData?.transactionId === transactionId
            );

            const result: Record<string, unknown> = {
              found: true,
              transactionId,
              blockHash: hash,
              blockDaaScore: blockData.block.header.daaScore,
              blockTimestamp: blockData.block.header.timestamp,
              isChainBlock: blockData.block.verboseData?.isChainBlock,
              blocksSearched: blocksChecked,
            };

            if (tx?.payload) {
              result.kpmPayload = parseKpmPayload(tx.payload);
            }

            return {
              content: [{
                type: "text" as const,
                text: JSON.stringify(result, null, 2),
              }],
            };
          }

          // Add parent hashes to queue (level 0 parents)
          const parents = blockData.block.header.parentsByLevel?.[0] ?? [];
          for (const parent of parents) {
            if (!visited.has(parent)) {
              queue.push(parent);
            }
          }
        } catch (err) {
          // Block might be pruned or unavailable — skip
          continue;
        }
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            found: false,
            transactionId,
            blocksSearched: blocksChecked,
            message: `Transaction not found in the last ${blocksChecked} blocks. It may be in an older block, not yet confirmed, or the transaction ID may be incorrect.`,
          }, null, 2),
        }],
      };
    }
  );

  // ── KPM-Specific Verification ──────────────────────────────────────

  server.registerTool(
    "kaspa_verify_kpm_anchor",
    {
      title: "Verify KPM Anchor Payload",
      description: `Given a block hash and transaction ID, verify that the transaction contains a valid KPM anchor payload and return the parsed anchor data.

This is the primary tool for independently verifying KPM's anchoring claims. Provide the kaspa_txid and block hash from KPM's event/receipt, and this tool will:
1. Fetch the block and find the transaction
2. Extract the transaction payload
3. Parse the KPM payload format (KPM1 || modeByte || hash32)
4. Return the anchor mode and hash for comparison with KPM's stored data

Args:
  - blockHash: block hash where KPM says the anchor tx lives
  - transactionId: the kaspa_txid from KPM's event record
  - expectedHash: (optional) the event hash or merkle root you expect to find — if provided, the tool verifies it matches

Returns:
  - verified: whether the KPM anchor was found and valid
  - anchorMode: INDIVIDUAL or MERKLE
  - hash: the 32-byte hash from the on-chain payload
  - hashMatch: whether expectedHash matches (if provided)`,
      inputSchema: {
        blockHash: z.string()
          .length(64, "Block hash must be 64 hex chars")
          .regex(/^[0-9a-f]+$/, "Must be lowercase hex")
          .describe("Block hash from KPM event record"),
        transactionId: z.string()
          .length(64, "Transaction ID must be 64 hex chars")
          .regex(/^[0-9a-f]+$/, "Must be lowercase hex")
          .describe("kaspa_txid from KPM event record"),
        expectedHash: z.string()
          .length(64, "Expected hash must be 64 hex chars")
          .regex(/^[0-9a-f]+$/, "Must be lowercase hex")
          .optional()
          .describe("Expected event hash or merkle root to verify against (optional)"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ blockHash, transactionId, expectedHash }) => {
      let block: Block;
      try {
        const data = (await client.request("getBlock", {
          hash: blockHash,
          includeTransactions: true,
        })) as unknown as GetBlockResponse;
        block = data.block;
      } catch (err) {
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              verified: false,
              error: `Failed to fetch block ${blockHash}: ${(err as Error).message}`,
            }, null, 2),
          }],
        };
      }

      // Find transaction
      const tx = block.transactions?.find(
        (t) => t.verboseData?.transactionId === transactionId
      );

      if (!tx) {
        // Check if tx ID is in the list but data wasn't included
        const txIds = block.verboseData?.transactionIds ?? [];
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              verified: false,
              error: txIds.includes(transactionId)
                ? "Transaction found in block's ID list but full data not available"
                : `Transaction ${transactionId} not found in block ${blockHash}`,
              blockTransactionCount: txIds.length,
            }, null, 2),
          }],
        };
      }

      // Parse payload
      if (!tx.payload) {
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              verified: false,
              error: "Transaction has no payload",
              transactionId,
            }, null, 2),
          }],
        };
      }

      const parsed = parseKpmPayload(tx.payload);

      if (!parsed.isKpmPayload) {
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              verified: false,
              error: "Transaction payload is not a valid KPM anchor (missing KPM1 magic bytes)",
              payloadPreview: tx.payload.substring(0, 20) + "...",
            }, null, 2),
          }],
        };
      }

      const result: Record<string, unknown> = {
        verified: true,
        transactionId,
        blockHash,
        blockDaaScore: block.header.daaScore,
        blockTimestamp: block.header.timestamp,
        anchorMode: parsed.anchorMode,
        hash: parsed.hash,
      };

      if (expectedHash !== undefined) {
        result.hashMatch = parsed.hash === expectedHash;
        result.expectedHash = expectedHash;
        if (!result.hashMatch) {
          result.verified = false;
          result.error = `Hash mismatch: on-chain=${parsed.hash}, expected=${expectedHash}`;
        }
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        }],
      };
    }
  );

  // ── Network / Supply ───────────────────────────────────────────────

  server.registerTool(
    "kaspa_get_coin_supply",
    {
      title: "Get Coin Supply",
      description: `Get the current circulating and maximum coin supply of Kaspa.

Returns:
  - circulatingSompi: current circulating supply in sompi
  - circulatingKas: formatted in KAS
  - maxSompi: maximum supply in sompi
  - maxKas: formatted in KAS`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async () => {
      const data = (await client.request("getCoinSupply")) as unknown as GetCoinSupplyResponse;
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            circulatingSompi: data.circulatingSompi,
            circulatingKas: sompiToKas(data.circulatingSompi),
            maxSompi: data.maxSompi,
            maxKas: sompiToKas(data.maxSompi),
          }, null, 2),
        }],
      };
    }
  );
}
