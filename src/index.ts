/**
 * Kaspa Node MCP Server
 *
 * MCP server for interacting with any rusty-kaspa node via wRPC Borsh.
 * Read-only blockchain queries plus wallet/signing tools gated behind
 * explicit operator opt-in. See README for the full security model.
 *
 * Network-agnostic: mainnet, testnet-10, testnet-11, testnet-12.
 *
 * Wallet activation (in order of preference):
 *   1. Encrypted file at ~/.kaspa-mcp/wallet.enc, unlocked at startup via
 *      /dev/tty prompt (preferred) or KASPA_WALLET_PASSWORD env (fallback).
 *      Requires KASPA_ENABLE_SIGNING=1 or KASPA_ENABLE_WALLET_SETUP=1.
 *   2. KASPA_MNEMONIC or KASPA_PRIVATE_KEY env var (no encrypted file).
 *
 * Environment variables (security-relevant):
 *   KASPA_ENABLE_HTTP                  - opt in to HTTP transport (off by default)
 *   KASPA_MCP_TOKEN                    - bearer token, required when HTTP enabled
 *   KASPA_ALLOWED_ORIGINS              - comma list (empty → reject any Origin header)
 *   KASPA_ENABLE_SIGNING               - register kaspa_send_transaction +
 *                                        kaspa_confirm_send_transaction
 *   KASPA_ENABLE_WALLET_SETUP          - register kaspa_generate_mnemonic +
 *                                        kaspa_save_wallet
 *   KASPA_MAX_SOMPI_PER_TX             - per-tx total spend cap (default 1000 KAS)
 *   KASPA_MAX_PENDING_TX               - max concurrent confirm tokens (default 50)
 *   KASPA_HTTP_RATE_CAPACITY           - HTTP token-bucket burst (default 60)
 *   KASPA_HTTP_RATE_REFILL_PER_SEC     - HTTP refill rate (default 2)
 *   KASPA_PREVIEW_RATE_CAPACITY        - preview burst (default 10)
 *   KASPA_PREVIEW_RATE_REFILL_PER_SEC  - preview refill (default 10/60)
 *   KASPA_SIGNING_RATE_CAPACITY        - signing burst (default 5)
 *   KASPA_SIGNING_RATE_REFILL_PER_SEC  - signing refill (default 5/60)
 *   KASPA_WALLET_PASSWORD              - env fallback for startup unlock
 *                                        (less preferred than TTY — leaks via
 *                                        shell history / process inspection)
 *
 * Audit log: append-only JSONL at ~/.kaspa-mcp/audit.log (chmod 600). Sensitive
 * field names (password, mnemonic, seed, secret, bearer, auth, private, token,
 * except *Hash suffixes) are scrubbed centrally. Rate-limit denials are
 * accumulated and flushed in ~5s windows so a denial loop cannot drive sync
 * disk I/O. See services/audit.ts and README for the full event/field list.
 *
 * Other env:
 *   KASPA_ENDPOINT       - wRPC Borsh WebSocket URL (default ws://127.0.0.1:17210)
 *   KASPA_NETWORK        - Network ID (optional, auto-detected)
 *   KASPA_ACCOUNT_INDEX  - BIP44 account index (default 0)
 *   PORT                 - HTTP port when KASPA_ENABLE_HTTP=1 (default 3000)
 *
 * Test-only env vars (NEVER set in production; both emit loud stderr warnings):
 *   KASPA_TEST_MOCK_TXSERVICE          - mock buildPreview/signAndSubmit
 *   KASPA_WALLET_UNLOCK_TIMEOUT_MS     - override 60s TTY unlock timeout
 *
 * Usage with Claude Code (stdio, read-only):
 *   KASPA_ENDPOINT=ws://127.0.0.1:17210 node dist/index.js
 *
 * Usage with HTTP (loopback only, bearer required):
 *   KASPA_ENABLE_HTTP=1 KASPA_MCP_TOKEN=$(openssl rand -hex 32) \
 *   KASPA_ENDPOINT=ws://127.0.0.1:17210 PORT=3001 node dist/index.js
 */

// WebSocket polyfill MUST be imported before kaspa-wasm
import "./services/setup.js";

// Importing `policy` first runs all env-flag validation. Bad config throws
// before any server state exists, so misconfiguration cannot silently
// weaken the security posture.
import { policy } from "./services/policy.js";
import {
  isAllowedHost,
  isAllowedOrigin,
  timingSafeBearer,
} from "./services/security.js";
import { TokenBucket } from "./services/rate-limit.js";
import { auditRateLimited, flushPendingAudit } from "./services/audit.js";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { KaspaWrpcClient } from "./services/kaspa-client.js";
import { registerTools } from "./tools/kaspa-tools.js";
import { registerWalletTools } from "./tools/wallet-tools.js";
import { walletFileExists } from "./services/wallet-store.js";
import { isWalletConfigured } from "./services/wallet.js";
import { tryStartupUnlock } from "./services/wallet-unlock.js";

const KASPA_ENDPOINT = process.env.KASPA_ENDPOINT ?? "ws://127.0.0.1:17210";
const KASPA_NETWORK = process.env.KASPA_NETWORK;

// The Kaspa client is a singleton — it owns one persistent wRPC connection
// shared across every transport / request. The MCP server is *not* a
// singleton anymore (see createMcpServer below).
const client = new KaspaWrpcClient({
  endpoint: KASPA_ENDPOINT,
  ...(KASPA_NETWORK ? { networkId: KASPA_NETWORK } : {}),
  connectTimeoutMs: 10000,
  requestTimeoutMs: 30000,
});

/**
 * Build a fresh McpServer with all tools registered.
 *
 * stdio uses one of these for the lifetime of the process. Streamable HTTP
 * builds one *per request*: the SDK Protocol layer is single-attach (calling
 * Server.connect() twice is undefined behavior), so two concurrent /mcp
 * requests against a shared singleton would race on transport assignment.
 *
 * Tool registration is fast (in-memory map writes) and stateless across
 * server instances — the underlying state lives in `client` and the future
 * pending-tx map (Phase 3), both of which are module-singletons.
 */
function createMcpServer(): McpServer {
  const s = new McpServer({
    name: "kaspa-node-mcp-server",
    version: "2.0.0",
  });
  registerTools(s, client);
  registerWalletTools(s, client);
  return s;
}

// Wallet status on startup. Unlock itself (TTY prompt or env fallback) is
// kicked off AFTER the transport is up — see runStdio / runHttp — so a
// stuck prompt cannot freeze MCP handshake.
if (isWalletConfigured()) {
  console.error("[kaspa-mcp] Wallet configured from environment variables.");
} else if (walletFileExists()) {
  console.error(
    "[kaspa-mcp] Encrypted wallet found. Will attempt unlock once transport is up " +
      "(KASPA_ENABLE_SIGNING / KASPA_ENABLE_WALLET_SETUP must be set)."
  );
} else {
  console.error(
    "[kaspa-mcp] No wallet configured. Set KASPA_MNEMONIC, or use the " +
      "wallet-setup mode to generate one."
  );
}

// ── Transport ────────────────────────────────────────────────────────

async function runStdio(): Promise<void> {
  // Start stdio transport immediately so Claude Code sees the server.
  // Kaspa node connection happens lazily on first tool call (see KaspaWrpcClient.request).
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[kaspa-mcp] stdio transport ready. Kaspa node connection is lazy (${KASPA_ENDPOINT}).`);

  // Fire-and-forget unlock. Runs in a child sh -c process so it does not
  // block the event loop while the user types. If the wallet stays locked
  // (no TTY, wrong password, no env fallback), signing/setup tools will
  // surface a clear error on first call.
  tryStartupUnlock().catch((e) => {
    console.error(
      `[kaspa-mcp] startup unlock task failed: ${
        e instanceof Error ? e.message : String(e)
      }`
    );
  });

  // Handle shutdown
  const shutdown = async () => {
    // Flush bucketed audit events before exit so a denial storm just
    // before shutdown still gets logged.
    flushPendingAudit();
    await client.disconnect();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function runHttp(): Promise<void> {
  // Caller invariant: policy.enableHttp must be true. Token presence is
  // already enforced by buildPolicy, but assert here so a future refactor
  // can't accidentally bypass it.
  if (!policy.enableHttp || !policy.bearerToken) {
    throw new Error(
      "runHttp() called without KASPA_ENABLE_HTTP=1 + KASPA_MCP_TOKEN set"
    );
  }
  const expectedToken = policy.bearerToken;
  const port = policy.httpPort;

  // Dynamic import for express — only needed in http mode
  const { default: express } = await import("express");
  const { StreamableHTTPServerTransport } = await import(
    "@modelcontextprotocol/sdk/server/streamableHttp.js"
  );

  // Lazy upstream connect: bring the listener up immediately so /health
  // and the auth chain are reachable even when the Kaspa node is down.
  // client.request() auto-connects on first use (see kaspa-client.ts:109),
  // so /mcp requests still see correct semantics.
  client.connect().catch((err) => {
    console.error(
      `[kaspa-mcp] Background connect to ${KASPA_ENDPOINT} failed: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  });

  const app = express();
  app.disable("x-powered-by");

  // ── Middleware order is load-bearing ─────────────────────────────────
  // 1. Defensive headers on every response.
  // 2. Host check (DNS-rebinding defense for browser callers hitting
  //    127.0.0.1 via an attacker-controlled hostname).
  // 3. Origin allowlist (only consulted when Origin is present).
  // 4. Process-global rate limit — sits AFTER Host/Origin so rejected
  //    cross-origin/rebinding probes don't drain the bucket, and BEFORE
  //    bearer + JSON parse so a token-guessing attacker can't cheaply
  //    spin parsing work.
  // 5. Bearer token compare with constant-time equality.
  // 6. JSON body parsing — *after* auth, with a strict size cap, so
  //    unauthenticated requests can never force JSON parsing work.
  // 7. Routes.
  // ─────────────────────────────────────────────────────────────────────

  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Referrer-Policy", "no-referrer");
    next();
  });

  app.use((req, res, next) => {
    if (!isAllowedHost(req.headers.host, port)) {
      res.status(403).json({ error: "host not allowed" });
      return;
    }
    next();
  });

  app.use((req, res, next) => {
    const origin = req.headers.origin;
    const originStr = Array.isArray(origin) ? origin[0] : origin;
    if (!isAllowedOrigin(originStr, policy.allowedOrigins)) {
      res.status(403).json({ error: "origin not allowed" });
      return;
    }
    next();
  });

  // Process-global rate limit. Loopback-only server means per-IP doesn't
  // give meaningful identity (see README threat model). Sits AFTER Host
  // and Origin so DNS-rebinding / cross-origin probes don't drain the
  // bucket, and BEFORE bearer auth + JSON parse so a token-guessing
  // attacker can't cheaply spin work.
  const httpBucket = new TokenBucket(
    policy.httpRateCapacity,
    policy.httpRateRefillPerSec,
  );
  app.use((_req, res, next) => {
    if (!httpBucket.consume()) {
      // Bucketed audit: every dry-bucket hit is counted in memory and a
      // single line is flushed every 5s, so an unauth loop cannot force
      // unbounded synchronous disk writes here.
      auditRateLimited("http");
      res.status(429).json({ error: "rate limit exceeded" });
      return;
    }
    next();
  });

  app.use((req, res, next) => {
    const auth = req.headers.authorization;
    const authStr = Array.isArray(auth) ? auth[0] : auth;
    if (!timingSafeBearer(authStr, expectedToken)) {
      res
        .status(401)
        .set("WWW-Authenticate", 'Bearer realm="kaspa-mcp"')
        .json({ error: "unauthorized" });
      return;
    }
    next();
  });

  // Body parser only runs after auth. 256kb is far above any realistic
  // MCP request and far below anything that would feel like a DoS vector.
  app.use(express.json({ limit: "256kb" }));

  app.post("/mcp", async (req, res) => {
    // Fresh McpServer + fresh transport per request. SDK Protocol is
    // single-attach; sharing a singleton across concurrent stateless HTTP
    // requests races on Server._transport. The McpServer is cheap; the
    // expensive resource (the wRPC client) is shared via closure.
    const reqServer = createMcpServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on("close", () => {
      transport.close();
      reqServer.close().catch(() => {});
    });
    try {
      await reqServer.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error(
        `[kaspa-mcp] /mcp request error: ${
          err instanceof Error ? err.message : String(err)
        }`
      );
      if (!res.headersSent) {
        res.status(500).json({ error: "internal error" });
      }
    }
  });

  // /health intentionally returns nothing about the upstream Kaspa endpoint;
  // any operator who needs that detail can read server logs. Same auth
  // chain applies (it sits behind the middleware above).
  app.get("/health", (_req, res) => {
    const healthy = client.isConnected();
    res
      .status(healthy ? 200 : 503)
      .json({ status: healthy ? "ok" : "disconnected" });
  });

  // 127.0.0.1 only — never bind 0.0.0.0. The Host header check is a second
  // line of defense against DNS rebinding once we're listening.
  app.listen(port, "127.0.0.1", () => {
    console.error(
      `[kaspa-mcp] HTTP MCP server bound to 127.0.0.1:${port} (auth required)`
    );
    // Same fire-and-forget unlock as stdio. The child-process-based prompt
    // means the express app keeps serving while the user types.
    tryStartupUnlock().catch((e) => {
      console.error(
        `[kaspa-mcp] startup unlock task failed: ${
          e instanceof Error ? e.message : String(e)
        }`
      );
    });
  });

  const shutdown = async () => {
    // Flush bucketed audit events before exit so a denial storm just
    // before shutdown still gets logged.
    flushPendingAudit();
    await client.disconnect();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// ── Main ─────────────────────────────────────────────────────────────

// Migration guard: the old `TRANSPORT=http` knob is no longer enough.
// HTTP now requires explicit opt-in via KASPA_ENABLE_HTTP=1 + a bearer
// token. Fail loudly so existing launch configs surface the change
// instead of silently falling back to stdio.
if (process.env.TRANSPORT === "http" && !policy.enableHttp) {
  console.error(
    "[kaspa-mcp] TRANSPORT=http requires KASPA_ENABLE_HTTP=1 and " +
      "KASPA_MCP_TOKEN (>=32 chars). See README for the new launch recipe."
  );
  process.exit(1);
}

if (policy.enableHttp) {
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
