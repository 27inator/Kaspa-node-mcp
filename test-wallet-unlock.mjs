/**
 * Phase 2 smoke test: startup wallet unlock.
 *
 * Verifies:
 *   1. tty.ts async prompts honor a timeout without blocking the event loop.
 *   2. With KASPA_ENABLE_SIGNING unset, no unlock happens (read-only mode).
 *   3. With KASPA_ENABLE_SIGNING=1 + KASPA_WALLET_PASSWORD env, the wallet
 *      unlocks at startup AFTER the MCP transport is up (server keeps
 *      responding to /health while unlock runs).
 *   4. KASPA_WALLET_PASSWORD with the wrong password leaves the wallet locked
 *      but does not crash the server.
 *   5. kaspa_load_wallet is no longer registered as a tool.
 */

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";

const PORT = 4140;
const TOKEN = "z".repeat(40);
const BASE = `http://127.0.0.1:${PORT}`;

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

// ──────────────────────────────────────────────────────────────────────
// Test 1: async TTY timeout / event loop responsiveness
// ──────────────────────────────────────────────────────────────────────
{
  const { promptPassword, isTtyAvailable } = await import("./dist/services/tty.js");
  if (!isTtyAvailable()) {
    check("tty.ts: async timeout fires", true, "skipped (no /dev/tty in this env)");
  } else {
    let evLoopTickedDuringPrompt = false;
    const tickInterval = setInterval(() => { evLoopTickedDuringPrompt = true; }, 100);
    let err;
    const start = Date.now();
    try {
      await promptPassword("(test) timeout: ", { timeoutMs: 600 });
    } catch (e) { err = e; }
    clearInterval(tickInterval);
    const elapsed = Date.now() - start;
    const ok =
      err && /timed out/i.test(err.message) &&
      elapsed >= 500 && elapsed < 3000 &&
      evLoopTickedDuringPrompt;
    check(
      "tty.ts: async timeout fires + event loop stays responsive",
      !!ok,
      `elapsed=${elapsed}ms tick=${evLoopTickedDuringPrompt} err=${err && err.message}`
    );
  }
}

// ──────────────────────────────────────────────────────────────────────
// Set up a temp wallet file we can target. Save with a known password.
// ──────────────────────────────────────────────────────────────────────
const TMP_HOME = mkdtempSync(join(tmpdir(), "kaspa-mcp-test-"));
const KNOWN_PASSWORD = "correct-horse-battery-staple";
const KNOWN_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Write the encrypted wallet under TMP_HOME/.kaspa-mcp/wallet.enc.
{
  const env = { ...process.env, HOME: TMP_HOME };
  const result = spawn("node", [
    "--input-type=module",
    "-e",
    `
    process.env.HOME = ${JSON.stringify(TMP_HOME)};
    const { saveEncryptedWallet } = await import("./dist/services/wallet-store.js");
    saveEncryptedWallet(
      ${JSON.stringify(KNOWN_MNEMONIC)},
      ${JSON.stringify(KNOWN_PASSWORD)},
      "testnet-12",
      0
    );
    `,
  ], { env, stdio: ["ignore", "pipe", "pipe"] });
  await new Promise((resolve) => result.on("close", resolve));
  const walletPath = join(TMP_HOME, ".kaspa-mcp", "wallet.enc");
  if (!existsSync(walletPath)) {
    throw new Error(`failed to create test wallet at ${walletPath}`);
  }
}

// ──────────────────────────────────────────────────────────────────────
// Helper: spawn a server with the temp HOME and wait for it to bind.
// ──────────────────────────────────────────────────────────────────────
async function spawnServer(extraEnv) {
  const env = {
    ...process.env,
    HOME: TMP_HOME,
    KASPA_ENABLE_HTTP: "1",
    KASPA_MCP_TOKEN: TOKEN,
    KASPA_ENDPOINT: "ws://127.0.0.1:1",
    PORT: String(PORT),
    // Bound the TTY prompt so a developer running this from a real terminal
    // doesn't wait 60s after a wrong-password test before the prompt times
    // out. CI sandboxes have no /dev/tty so this is a no-op there.
    KASPA_WALLET_UNLOCK_TIMEOUT_MS: "300",
    ...extraEnv,
  };
  // Don't inherit any KASPA_MNEMONIC / KASPA_PRIVATE_KEY so the wallet must
  // come from the encrypted file path.
  delete env.KASPA_MNEMONIC;
  delete env.KASPA_PRIVATE_KEY;

  const proc = spawn("node", ["dist/index.js"], { env, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  proc.stderr.on("data", (b) => (stderr += b.toString()));

  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/health`, {
        headers: { authorization: `Bearer ${TOKEN}` },
      });
      if (r.status === 200 || r.status === 503) return { proc, stderrRef: () => stderr };
    } catch {}
    await sleep(100);
  }
  proc.kill("SIGTERM");
  throw new Error(`server did not bind\nstderr:\n${stderr}`);
}

async function callToolsList(proc_unused, stderrRef_unused) {
  await fetch(`${BASE}/mcp`, {
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
        clientInfo: { name: "phase2-smoke", version: "0.0.1" },
      },
    }),
  });
  const r = await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 2, method: "tools/list", params: {},
    }),
  });
  return r.text();
}

try {
  // ────────────────────────────────────────────────────────────────────
  // Test 2: read-only server (no signing flag) does NOT prompt or unlock.
  //         /health responds immediately, no "Wallet unlocked" log line.
  // ────────────────────────────────────────────────────────────────────
  {
    const { proc, stderrRef } = await spawnServer({});
    await sleep(500); // give the (non-)unlock task a chance
    proc.kill("SIGTERM");
    await sleep(200);
    const log = stderrRef();
    const ok =
      !log.includes("Wallet unlocked via") &&
      !log.includes("Prompting for wallet password");
    check("read-only mode: no unlock attempted", ok, log.split("\n").slice(0, 3).join(" | "));
  }

  // ────────────────────────────────────────────────────────────────────
  // Test 3: signing enabled + correct env password → unlock succeeds AFTER
  //         transport is up. /health stays responsive throughout. Env is
  //         tried FIRST (before any TTY prompt), so even on a TTY-available
  //         host the unlock log appears within ~1s.
  // ────────────────────────────────────────────────────────────────────
  {
    const t0 = Date.now();
    const { proc, stderrRef } = await spawnServer({
      KASPA_ENABLE_SIGNING: "1",
      KASPA_WALLET_PASSWORD: KNOWN_PASSWORD,
    });
    // /health was reachable at this point (spawnServer waited on it).
    // Wait briefly for the unlock task to complete.
    await sleep(800);
    // Confirm /health still responds (server didn't deadlock during unlock).
    const r = await fetch(`${BASE}/health`, {
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    proc.kill("SIGTERM");
    await sleep(200);
    const elapsed = Date.now() - t0;
    const log = stderrRef();
    // Env-first: the env-trial log appears BEFORE any TTY prompt log. A
    // TTY-prompt line followed by env would indicate we regressed back to
    // TTY-first. Within the elapsed bound, that ordering is enforced.
    const idxEnv = log.indexOf("Trying KASPA_WALLET_PASSWORD env");
    const idxTty = log.indexOf("Prompting for wallet password");
    const ok =
      log.includes("Wallet unlocked via KASPA_WALLET_PASSWORD env") &&
      (r.status === 200 || r.status === 503) &&
      idxEnv >= 0 &&
      (idxTty < 0 || idxEnv < idxTty);
    check(
      "signing+env: env-first, unlocked, /health responsive",
      ok,
      `health=${r.status} elapsed=${elapsed}ms idxEnv=${idxEnv} idxTty=${idxTty}`
    );
  }

  // ────────────────────────────────────────────────────────────────────
  // Test 4: signing enabled + WRONG env password → wallet stays locked,
  //         server does not crash. /health still responds.
  // ────────────────────────────────────────────────────────────────────
  {
    const { proc, stderrRef } = await spawnServer({
      KASPA_ENABLE_SIGNING: "1",
      KASPA_WALLET_PASSWORD: "obviously-wrong",
    });
    await sleep(800);
    const r = await fetch(`${BASE}/health`, {
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    proc.kill("SIGTERM");
    await sleep(200);
    const log = stderrRef();
    const ok =
      log.includes("did not decrypt") &&
      log.includes("Wallet remains locked") &&
      (r.status === 200 || r.status === 503);
    check(
      "signing+wrong password: wallet locked, server alive",
      ok,
      `health=${r.status} log_has_remains_locked=${log.includes("Wallet remains locked")}`
    );
  }

  // ────────────────────────────────────────────────────────────────────
  // Test 5: kaspa_load_wallet is no longer in tools/list.
  // ────────────────────────────────────────────────────────────────────
  {
    // Use a different port — previous tests' kills may not have released
    // PORT in time for a fresh listen() to succeed cleanly.
    const localBase = `http://127.0.0.1:${PORT + 1}`;
    const env = {
      ...process.env,
      HOME: TMP_HOME,
      KASPA_ENABLE_HTTP: "1",
      KASPA_MCP_TOKEN: TOKEN,
      KASPA_ENDPOINT: "ws://127.0.0.1:1",
      PORT: String(PORT + 1),
    };
    delete env.KASPA_MNEMONIC;
    delete env.KASPA_PRIVATE_KEY;
    const proc = spawn("node", ["dist/index.js"], { env, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    proc.stderr.on("data", (b) => (stderr += b.toString()));

    // Wait for bind
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      try {
        const r = await fetch(`${localBase}/health`, { headers: { authorization: `Bearer ${TOKEN}` } });
        if (r.status === 200 || r.status === 503) break;
      } catch {}
      await sleep(100);
    }

    await fetch(`${localBase}/mcp`, {
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
          clientInfo: { name: "phase2-smoke", version: "0.0.1" },
        },
      }),
    });
    const r = await fetch(`${localBase}/mcp`, {
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
    await sleep(300);

    // Match the literal "name":"kaspa_load_wallet" registration, not the
    // bare string — descriptions/error hints may still mention old tool
    // names harmlessly.
    let toolNames = [];
    try {
      const parsed = JSON.parse(body);
      toolNames = (parsed.result?.tools ?? []).map((t) => t.name);
    } catch { /* fall through with empty list */ }
    const hasLoadWallet = toolNames.includes("kaspa_load_wallet");
    const hasGetMyAddress = toolNames.includes("kaspa_get_my_address");
    const ok = !hasLoadWallet && hasGetMyAddress;
    check(
      "kaspa_load_wallet removed from tools/list",
      ok,
      `tools=${toolNames.length} hasGetMyAddress=${hasGetMyAddress} hasLoadWallet=${hasLoadWallet}`
    );
  }
} finally {
  rmSync(TMP_HOME, { recursive: true, force: true });
}

const failed = results.filter((r) => !r.ok);
if (failed.length) {
  console.error(`\n${failed.length}/${results.length} checks failed`);
  process.exit(1);
}
console.log(`\nall ${results.length} checks passed`);
