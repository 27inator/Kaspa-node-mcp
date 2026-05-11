/**
 * Phase 3e HTTP integration test: two-step send flow across two HTTP
 * requests proves the pending map is module-singleton, not per-McpServer.
 *
 * Setup:
 *   - KASPA_TEST_MOCK_TXSERVICE=1 makes buildPreview/signAndSubmit return
 *     canned data, so the test runs without a live Kaspa node.
 *   - KASPA_ENABLE_SIGNING=1 registers the two-step tools.
 *   - KASPA_MNEMONIC gives the server a wallet so isWalletConfigured() is
 *     true at the tool layer.
 *
 * Each HTTP /mcp POST creates a fresh McpServer (per Phase 1 lifecycle
 * fix). If the pending map were tied to McpServer instance scope, the
 * second request would not find the entry created by the first. The fact
 * that it does prove the map's module-singleton property.
 */

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { request as httpRequest } from "node:http";

/**
 * http.request-based POST/GET. Node's built-in fetch was failing on
 * back-to-back loopback requests in this sandbox while curl worked
 * against the same listener — switching to http.request avoids that.
 */
function rawRequest({ method = "GET", path = "/", headers = {}, body, port }) {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, path, method, headers },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") })
        );
      }
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

const PORT = 4190;
const TOKEN = "h".repeat(40);
const BASE = `http://127.0.0.1:${PORT}`;
// Address derived from the standard "abandon ... about" mnemonic at BIP44
// account 0 on testnet-12. Self-sending is structurally valid — and we're
// running with mocked tx service so the broadcast path doesn't matter.
const RECIPIENT =
  "kaspatest:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9ssxd5s7gn";

const env = {
  ...process.env,
  KASPA_ENABLE_HTTP: "1",
  KASPA_MCP_TOKEN: TOKEN,
  KASPA_ENDPOINT: "ws://127.0.0.1:1",
  PORT: String(PORT),
  KASPA_ENABLE_SIGNING: "1",
  KASPA_TEST_MOCK_TXSERVICE: "1",
  KASPA_MNEMONIC:
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  KASPA_NETWORK: "testnet-12",
  // Disable rate limits in this test — Phase 5's HTTP integration tests
  // live in test-audit-rate-limit.mjs.
  KASPA_HTTP_RATE_CAPACITY: "10000",
  KASPA_HTTP_RATE_REFILL_PER_SEC: "10000",
  KASPA_SIGNING_RATE_CAPACITY: "10000",
  KASPA_SIGNING_RATE_REFILL_PER_SEC: "10000",
};
delete env.KASPA_WALLET_PASSWORD;
delete env.KASPA_PRIVATE_KEY;

const server = spawn("node", ["dist/index.js"], { env, stdio: ["ignore", "ignore", "pipe"] });
let stderr = "";
server.stderr.on("data", (b) => (stderr += b.toString()));

async function waitForListener() {
  const deadline = Date.now() + 8000;
  let lastErr = "";
  let lastStatus = -1;
  while (Date.now() < deadline) {
    try {
      const r = await rawRequest({
        path: "/health",
        port: PORT,
        headers: { authorization: `Bearer ${TOKEN}` },
      });
      lastStatus = r.status;
      if (r.status === 200 || r.status === 503) return;
    } catch (e) {
      lastErr = e?.message ?? String(e);
    }
    await sleep(120);
  }
  throw new Error(
    `server didn't bind. lastStatus=${lastStatus} lastErr=${lastErr}\n` +
      `stderr:\n${stderr}`
  );
}

/**
 * Issue an isolated HTTP /mcp request that initializes then runs one
 * tools/call in a SINGLE Streamable-HTTP exchange. The reason: each /mcp
 * POST creates a fresh McpServer (Phase 1), so initializing and calling
 * in two separate fetch() calls would also each be a fresh server. To
 * exercise the actual two-request → two-McpServer property, both requests
 * must do their own initialize+call.
 *
 * Streamable HTTP with enableJsonResponse:true accepts a single JSON-RPC
 * message per request, so initialize and tools/call go in separate
 * fetch()'es within the same logical "client session" — which here is just
 * the same wire shape. Each fetch lands on a fresh McpServer, so we get
 * the per-McpServer scope we want to test the singleton against.
 */
async function callTool(toolName, args) {
  await rawRequest({
    method: "POST",
    path: "/mcp",
    port: PORT,
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: {
        protocolVersion: "2024-11-05", capabilities: {},
        clientInfo: { name: "phase3e", version: "0.0.1" },
      },
    }),
  });
  const r = await rawRequest({
    method: "POST",
    path: "/mcp",
    port: PORT,
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 2, method: "tools/call",
      params: { name: toolName, arguments: args },
    }),
  });
  return r.body;
}

function extractToolJson(body) {
  // Streamable HTTP wraps tool results in { result: { content: [{ text: "<json>" }] } }
  try {
    const top = JSON.parse(body);
    const text = top?.result?.content?.[0]?.text;
    if (typeof text !== "string") return null;
    try { return JSON.parse(text); } catch { return { _raw: text }; }
  } catch {
    return null;
  }
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

try {
  await waitForListener();

  // ── HTTP REQUEST 1: kaspa_send_transaction → expect confirm_token ──
  const body1 = await callTool("kaspa_send_transaction", {
    to: RECIPIENT,
    amount: "1.5",
  });
  const r1 = extractToolJson(body1);
  const tokenOk =
    r1?.status === "preview_pending_confirmation" &&
    typeof r1?.confirm_token === "string" &&
    /^[0-9a-f]{32}$/.test(r1.confirm_token) &&
    typeof r1?.digest === "string" &&
    /^[0-9a-f]{8}$/.test(r1.digest);
  check(
    "request 1: kaspa_send_transaction returns 32-hex confirm_token + 8-hex digest",
    tokenOk,
    `status=${r1?.status} tokenLen=${r1?.confirm_token?.length} digestLen=${r1?.digest?.length} body=${body1.slice(0, 250)}`,
  );
  if (!tokenOk) throw new Error("can't continue without a token");

  // ── HTTP REQUEST 2: kaspa_confirm_send_transaction(token) ──
  // The client doesn't declare elicitation capability and there's no /dev/tty
  // available in this test process, so the resolver falls through to
  // "no_channel". That's the CORRECT outcome here: we want to prove the
  // map lookup succeeded across the McpServer boundary, NOT that we
  // happen to have a working approval channel in this sandbox.
  const body2 = await callTool("kaspa_confirm_send_transaction", {
    confirm_token: r1.confirm_token,
  });
  const r2 = extractToolJson(body2);
  const lookupOk =
    typeof r2 === "object" &&
    // Either we got "no_channel" (token was found, approval failed) — the
    // happy proof of cross-request lookup — OR we got "submitted" if the
    // channel somehow worked. Both prove the token was visible to the
    // second McpServer. What we MUST NOT see is "unknown, expired, or
    // already used".
    !(r2?.error ?? "").includes("unknown, expired, or already used");
  check(
    "request 2: token from request 1's McpServer is visible to request 2's McpServer",
    lookupOk,
    `reason=${r2?.reason ?? r2?.status ?? "?"} error=${(r2?.error ?? "").slice(0, 80)}`,
  );

  // ── HTTP REQUEST 3: replay same token → must be already-used ──
  // Even though request 2 failed approval ("no_channel"), the token was
  // consumed (deleted) by consumePending. A replay must hit the generic
  // missing/used/expired error.
  const body3 = await callTool("kaspa_confirm_send_transaction", {
    confirm_token: r1.confirm_token,
  });
  const r3 = extractToolJson(body3);
  const replayOk =
    typeof r3 === "object" &&
    (r3?.error ?? "").includes("unknown, expired, or already used");
  check(
    "request 3: replaying the consumed token returns generic-error",
    replayOk,
    `error=${(r3?.error ?? "").slice(0, 80)}`,
  );
} finally {
  server.kill("SIGTERM");
  await sleep(300);
}

const failed = results.filter((r) => !r.ok);
if (failed.length) {
  console.error(`\n${failed.length}/${results.length} checks failed`);
  console.error("server stderr (last 800 chars):\n" + stderr.slice(-800));
  process.exit(1);
}
console.log(`\nall ${results.length} checks passed`);
