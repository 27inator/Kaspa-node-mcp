/**
 * Phase 4 smoke test: tool input validation.
 *
 * Spawns the MCP server over HTTP (with a known token) and exercises the
 * validation surface that Phase 4 introduced:
 *   - Bad address shape on kaspa_get_balance → tool error
 *   - Bad checksum (well-shaped but invalid CashAddr) → tool error
 *   - Bad block hash length → tool error
 *   - Oversized payload on kaspa_send_transaction → tool error
 *
 * Uses a guaranteed-fail KASPA_ENDPOINT so we don't depend on a live node;
 * validation runs before any RPC is attempted.
 */

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const PORT = 4138;
const TOKEN = "y".repeat(40);
const BASE = `http://127.0.0.1:${PORT}`;

const env = {
  ...process.env,
  KASPA_ENABLE_HTTP: "1",
  KASPA_MCP_TOKEN: TOKEN,
  KASPA_ENDPOINT: "ws://127.0.0.1:1",
  PORT: String(PORT),
  // Phase 3a gates kaspa_send_transaction behind KASPA_ENABLE_SIGNING=1.
  // This test verifies the tool's Zod input validation, so signing must be
  // enabled — otherwise the tool isn't registered and we test "tool not
  // found" instead of the validation we care about.
  KASPA_ENABLE_SIGNING: "1",
};

const server = spawn("node", ["dist/index.js"], { env, stdio: ["ignore", "ignore", "pipe"] });
let stderr = "";
server.stderr.on("data", (b) => { stderr += b.toString(); });

async function waitForListener(timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/health`, { headers: { authorization: `Bearer ${TOKEN}` } });
      if (r.status === 503 || r.status === 200) return;
    } catch {}
    await sleep(100);
  }
  throw new Error(`server did not start within ${timeoutMs}ms\nstderr:\n${stderr}`);
}

async function callTool(name, args) {
  // initialize → tools/call
  const init = await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "phase4-smoke", version: "0.0.1" },
      },
    }),
  });
  if (init.status !== 200) throw new Error(`initialize failed: ${init.status}`);

  const r = await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 2, method: "tools/call",
      params: { name, arguments: args },
    }),
  });
  return { status: r.status, body: await r.text() };
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

try {
  await waitForListener();

  // 1. Bad address shape — fails Zod schema (must reject before reaching node)
  {
    const r = await callTool("kaspa_get_balance", { address: "not-a-kaspa-address" });
    // Schema-level rejection comes back as a JSON-RPC error or a tool error;
    // either way the body should NOT show a successful balance lookup.
    const ok = !r.body.includes('"balance"') && r.body.toLowerCase().includes("address");
    check("bad address shape rejected", ok, `body=${r.body.slice(0, 200)}`);
  }

  // 2. Well-shaped but bad checksum (right prefix + valid charset, wrong checksum)
  //    All q's pass charset/length checks but fail kaspa.Address checksum.
  {
    const r = await callTool("kaspa_get_balance", {
      address: "kaspatest:" + "q".repeat(60),
    });
    // Handler-level checksum validation produces an isError tool result.
    // The string "invalid Kaspa address" is what address-validator throws.
    const ok = r.body.includes("invalid Kaspa address") || r.body.toLowerCase().includes("address");
    check("bad checksum rejected", ok, `body=${r.body.slice(0, 200)}`);
  }

  // 3. Bad block hash length
  {
    const r = await callTool("kaspa_get_block", { hash: "deadbeef" });
    const ok = !r.body.includes('"block"') &&
      (r.body.includes("64") || r.body.toLowerCase().includes("hex"));
    check("short block hash rejected", ok, `body=${r.body.slice(0, 200)}`);
  }

  // 4. Oversized payload on send tool
  {
    const huge = "ab".repeat(11_000); // 22000 hex chars > 20000 cap
    const r = await callTool("kaspa_send_transaction", {
      to: "kaspatest:qzr0kzh7ypvfczks24mcakmccfd2drm6tjmprr8h0w6m6sn3rspqyfp7chx0u",
      amount: "1.0",
      payload: huge,
    });
    const ok = !r.body.includes('"txId"') &&
      (r.body.includes("20") || r.body.toLowerCase().includes("payload"));
    check("oversized payload rejected", ok, `body=${r.body.slice(0, 200)}`);
  }

  // 5. Sompi over the per-tx cap — handler enforces policy.maxSompiPerTx.
  //    Default cap is 1000 KAS = 100_000_000_000 sompi. 9999 KAS exceeds it.
  //    No wallet configured in this test, so we expect either the cap message
  //    OR the "no active wallet" message — both indicate the request did not
  //    reach the broadcaster. We assert no successful txId.
  {
    const r = await callTool("kaspa_send_transaction", {
      to: "kaspatest:qzr0kzh7ypvfczks24mcakmccfd2drm6tjmprr8h0w6m6sn3rspqyfp7chx0u",
      amount: "9999",
    });
    const ok = !r.body.includes('"txId"');
    check("9999 KAS send blocked (cap or no-wallet)", ok, `body=${r.body.slice(0, 200)}`);
  }
} finally {
  server.kill("SIGTERM");
  await sleep(200);
}

const failed = results.filter((r) => !r.ok);
if (failed.length) {
  console.error(`\n${failed.length}/${results.length} checks failed`);
  console.error("server stderr:\n" + stderr);
  process.exit(1);
}
console.log(`\nall ${results.length} checks passed`);
