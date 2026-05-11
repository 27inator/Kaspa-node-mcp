/**
 * Phase 3a smoke test: tool registration gating.
 *
 * Verifies, via the wire protocol's tools/list, that:
 *   1. With no flags: send/save/generate are NOT advertised.
 *   2. With KASPA_ENABLE_SIGNING=1 only: send IS advertised; save/generate
 *      are still NOT.
 *   3. With KASPA_ENABLE_WALLET_SETUP=1 only: save+generate ARE advertised;
 *      send is still NOT.
 *   4. With both flags: all three are advertised.
 *
 * Read-only tools (kaspa_get_info, kaspa_get_balance, kaspa_estimate_fee,
 * kaspa_get_my_address, etc.) are present in every configuration.
 */

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const TOKEN = "g".repeat(40);

const SETUP_TOOLS = ["kaspa_save_wallet", "kaspa_generate_mnemonic"];
const SIGNING_TOOLS = ["kaspa_send_transaction"];
const ALWAYS_TOOLS = [
  "kaspa_get_info",
  "kaspa_get_my_address",
  "kaspa_estimate_fee",
];

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

let nextPort = 4150;
async function listToolsWith(extraEnv) {
  const port = nextPort++;
  const env = {
    ...process.env,
    KASPA_ENABLE_HTTP: "1",
    KASPA_MCP_TOKEN: TOKEN,
    KASPA_ENDPOINT: "ws://127.0.0.1:1",
    PORT: String(port),
    ...extraEnv,
  };
  delete env.KASPA_MNEMONIC;
  delete env.KASPA_PRIVATE_KEY;

  const proc = spawn("node", ["dist/index.js"], { env, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  proc.stderr.on("data", (b) => (stderr += b.toString()));

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${base}/health`, { headers: { authorization: `Bearer ${TOKEN}` } });
      if (r.status === 200 || r.status === 503) break;
    } catch {}
    await sleep(80);
  }

  await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: {
        protocolVersion: "2024-11-05", capabilities: {},
        clientInfo: { name: "phase3a-smoke", version: "0.0.1" },
      },
    }),
  });
  const r = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
  });
  const body = await r.text();
  proc.kill("SIGTERM");
  await sleep(250);

  let toolNames = [];
  try {
    toolNames = (JSON.parse(body).result?.tools ?? []).map((t) => t.name);
  } catch { /* */ }
  return { toolNames, stderr };
}

function assertSet(label, names, mustHave, mustLack) {
  const missing = mustHave.filter((n) => !names.includes(n));
  const leaked = mustLack.filter((n) => names.includes(n));
  const ok = missing.length === 0 && leaked.length === 0;
  check(label, ok, `missing=${missing.join(",")||"-"} leaked=${leaked.join(",")||"-"} total=${names.length}`);
}

// 1. No flags → no signing/setup tools
{
  const { toolNames } = await listToolsWith({});
  assertSet("no flags: only read-only tools", toolNames, ALWAYS_TOOLS, [...SIGNING_TOOLS, ...SETUP_TOOLS]);
}

// 2. Signing only
{
  const { toolNames } = await listToolsWith({ KASPA_ENABLE_SIGNING: "1" });
  assertSet(
    "signing only: send advertised, setup gated out",
    toolNames,
    [...ALWAYS_TOOLS, ...SIGNING_TOOLS],
    SETUP_TOOLS,
  );
}

// 3. Setup only
{
  const { toolNames } = await listToolsWith({ KASPA_ENABLE_WALLET_SETUP: "1" });
  assertSet(
    "setup only: save+generate advertised, send gated out",
    toolNames,
    [...ALWAYS_TOOLS, ...SETUP_TOOLS],
    SIGNING_TOOLS,
  );
}

// 4. Both flags
{
  const { toolNames } = await listToolsWith({
    KASPA_ENABLE_SIGNING: "1",
    KASPA_ENABLE_WALLET_SETUP: "1",
  });
  assertSet(
    "both flags: send + save + generate all advertised",
    toolNames,
    [...ALWAYS_TOOLS, ...SIGNING_TOOLS, ...SETUP_TOOLS],
    [],
  );
}

const failed = results.filter((r) => !r.ok);
if (failed.length) {
  console.error(`\n${failed.length}/${results.length} checks failed`);
  process.exit(1);
}
console.log(`\nall ${results.length} checks passed`);
