/**
 * Kaspa Node MCP Server
 *
 * MCP server for interacting with any rusty-kaspa node via wRPC Borsh.
 * 17 tools: read-only blockchain queries, BIP39/BIP44 wallet management
 * with AES-256-GCM encrypted persistence, transaction submission with
 * payload support, and KPM anchor verification.
 *
 * Network-agnostic: mainnet, testnet-10, testnet-11, testnet-12, devnet.
 *
 * Wallet options (pick one):
 *   1. Encrypted file: kaspa_generate_mnemonic → kaspa_save_wallet(password)
 *      Next session: kaspa_load_wallet(password). No env vars needed.
 *   2. Environment: KASPA_MNEMONIC or KASPA_PRIVATE_KEY
 *
 * Environment variables:
 *   KASPA_ENDPOINT       - wRPC Borsh WebSocket URL (default: ws://127.0.0.1:17210)
 *   KASPA_NETWORK        - Network ID (optional, auto-detected from node)
 *   KASPA_MNEMONIC       - BIP39 mnemonic phrase (optional if using encrypted wallet)
 *   KASPA_PRIVATE_KEY    - Hex private key, alternative to mnemonic (optional)
 *   KASPA_ACCOUNT_INDEX  - BIP44 account index (default: 0)
 *   TRANSPORT            - "stdio" (default) or "http"
 *   PORT                 - HTTP port when using http transport (default: 3000)
 *
 * Usage with Claude Code (stdio):
 *   KASPA_ENDPOINT=ws://127.0.0.1:17210 node dist/index.js
 *
 * Usage with OpenClaw (http):
 *   KASPA_ENDPOINT=ws://127.0.0.1:17210 TRANSPORT=http PORT=3001 node dist/index.js
 */

// WebSocket polyfill MUST be imported before kaspa-wasm
import "./services/setup.js";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { KaspaWrpcClient } from "./services/kaspa-client.js";
import { registerTools } from "./tools/kaspa-tools.js";
import { registerWalletTools } from "./tools/wallet-tools.js";
import { walletFileExists } from "./services/wallet-store.js";
import { isWalletConfigured } from "./services/wallet.js";

const KASPA_ENDPOINT = process.env.KASPA_ENDPOINT ?? "ws://127.0.0.1:17210";
const KASPA_NETWORK = process.env.KASPA_NETWORK;

const server = new McpServer({
  name: "kaspa-node-mcp-server",
  version: "2.0.0",
});

const client = new KaspaWrpcClient({
  endpoint: KASPA_ENDPOINT,
  ...(KASPA_NETWORK ? { networkId: KASPA_NETWORK } : {}),
  connectTimeoutMs: 10000,
  requestTimeoutMs: 30000,
});

// Register all tools
registerTools(server, client);
registerWalletTools(server, client);

// Wallet status on startup
if (isWalletConfigured()) {
  console.error("[kaspa-mcp] Wallet configured from environment variables.");
} else if (walletFileExists()) {
  console.error("[kaspa-mcp] Encrypted wallet found. Use kaspa_load_wallet to unlock.");
} else {
  console.error("[kaspa-mcp] No wallet configured. Use kaspa_generate_mnemonic or set KASPA_MNEMONIC.");
}

// ── Transport ────────────────────────────────────────────────────────

async function runStdio(): Promise<void> {
  // Start stdio transport immediately so Claude Code sees the server.
  // Kaspa node connection happens lazily on first tool call (see KaspaWrpcClient.request).
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[kaspa-mcp] stdio transport ready. Kaspa node connection is lazy (${KASPA_ENDPOINT}).`);

  // Handle shutdown
  process.on("SIGINT", async () => {
    await client.disconnect();
    process.exit(0);
  });
  process.on("SIGTERM", async () => {
    await client.disconnect();
    process.exit(0);
  });
}

async function runHttp(): Promise<void> {
  // Dynamic import for express — only needed in http mode
  const { default: express } = await import("express");
  const { StreamableHTTPServerTransport } = await import(
    "@modelcontextprotocol/sdk/server/streamableHttp.js"
  );

  console.error(`[kaspa-mcp] Connecting to Kaspa node at ${KASPA_ENDPOINT}...`);
  await client.connect();
  console.error(`[kaspa-mcp] Connected. Starting HTTP transport.`);

  const app = express();
  app.use(express.json());

  app.post("/mcp", async (req, res) => {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on("close", () => transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  // Health endpoint
  app.get("/health", async (_req, res) => {
    const healthy = client.isConnected();
    res.status(healthy ? 200 : 503).json({
      status: healthy ? "ok" : "disconnected",
      endpoint: KASPA_ENDPOINT,
    });
  });

  const port = parseInt(process.env.PORT ?? "3000", 10);
  app.listen(port, () => {
    console.error(`[kaspa-mcp] HTTP MCP server running on http://localhost:${port}/mcp`);
    console.error(`[kaspa-mcp] Health check: http://localhost:${port}/health`);
  });

  process.on("SIGINT", async () => {
    await client.disconnect();
    process.exit(0);
  });
}

// ── Main ─────────────────────────────────────────────────────────────

const transport = process.env.TRANSPORT ?? "stdio";
if (transport === "http") {
  runHttp().catch((error) => {
    console.error("[kaspa-mcp] Server error:", error);
    process.exit(1);
  });
} else {
  runStdio().catch((error) => {
    console.error("[kaspa-mcp] Server error:", error);
    process.exit(1);
  });
}
