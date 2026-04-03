/**
 * Kaspa Node MCP Server
 *
 * Read-only MCP server for interacting with any rusty-kaspa node
 * via wRPC JSON over WebSocket.
 *
 * Environment variables:
 *   KASPA_ENDPOINT  - wRPC JSON WebSocket URL (default: ws://localhost:18210)
 *   TRANSPORT       - "stdio" (default) or "http"
 *   PORT            - HTTP port when using http transport (default: 3000)
 *
 * Usage with Claude Code (stdio):
 *   KASPA_ENDPOINT=ws://localhost:18210 node dist/index.js
 *
 * Usage with OpenClaw (http):
 *   KASPA_ENDPOINT=ws://localhost:18210 TRANSPORT=http PORT=3001 node dist/index.js
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { KaspaWrpcClient } from "./services/kaspa-client.js";
import { registerTools } from "./tools/kaspa-tools.js";

const KASPA_ENDPOINT = process.env.KASPA_ENDPOINT ?? "ws://localhost:18210";

const server = new McpServer({
  name: "kaspa-node-mcp-server",
  version: "1.0.0",
});

const client = new KaspaWrpcClient({
  endpoint: KASPA_ENDPOINT,
  connectTimeoutMs: 10000,
  requestTimeoutMs: 30000,
  autoReconnect: true,
  reconnectDelayMs: 3000,
});

// Register all tools
registerTools(server, client);

// ── Transport ────────────────────────────────────────────────────────

async function runStdio(): Promise<void> {
  // Connect to Kaspa node first
  console.error(`[kaspa-mcp] Connecting to Kaspa node at ${KASPA_ENDPOINT}...`);
  await client.connect();
  console.error(`[kaspa-mcp] Connected. Starting stdio transport.`);

  const transport = new StdioServerTransport();
  await server.connect(transport);

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
