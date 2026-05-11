/**
 * Phase 3c smoke test: kaspa_save_wallet rewrite.
 *
 * In-process tests via the deps-injection seam on saveWalletHandler.
 *
 * Verifies:
 *   1. tools/list advertises kaspa_save_wallet with EMPTY input schema
 *      (no `password` arg).
 *   2. No active wallet → refuse, no file, no leak.
 *   3. Private-key-only wallet → refuse, no file.
 *   4. Existing wallet file → refuse, recovery hint with `mv ... .bak`.
 *   5. No password source (no env, no TTY) → refuse, no file.
 *   6. Empty env password → refuse, no file.
 *   7. Empty TTY password → refuse, no file.
 *   8. Env path: env set non-empty → success, file decryptable, source="env".
 *   9. TTY path: env unset, mock returns password → success, file decryptable,
 *      source="tty".
 *  10. No password leak: tool result body never contains the password.
 */

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP_HOME = mkdtempSync(join(tmpdir(), "kaspa-mcp-savewallet-"));
process.env.HOME = TMP_HOME;
delete process.env.KASPA_WALLET_PASSWORD;
delete process.env.KASPA_MNEMONIC;
delete process.env.KASPA_PRIVATE_KEY;
process.env.KASPA_ENABLE_WALLET_SETUP = "1";

await import("./dist/services/setup.js");

const { saveWalletHandler } = await import("./dist/tools/wallet-tools.js");
const { _setTtyImplForTests, _resetTtyImpl } = await import("./dist/services/tty.js");
const {
  walletFileExists,
  getWalletFilePath,
  loadEncryptedWallet,
  saveEncryptedWallet,
} = await import("./dist/services/wallet-store.js");
const {
  setWalletInstance,
  clearWalletInstance,
  KaspaWallet,
} = await import("./dist/services/wallet.js");

const KNOWN_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ENV_PW = "env-secret-password-1234567890";
const TTY_PW = "tty-secret-password-abcdefghij";

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

function bodyOf(r) { return r.content[0].text; }
function isErr(r) { return r.isError === true; }

function freshTtyMock(passwordToReturn) {
  const captured = { passwordPrompts: 0 };
  const impl = {
    isTtyAvailable: () => true,
    promptPassword: async () => {
      captured.passwordPrompts++;
      return passwordToReturn;
    },
    promptLine: async () => "",
    writeMnemonic: async () => {},
  };
  return { captured, impl };
}

function activateMnemonicWallet() {
  const wallet = KaspaWallet.fromMnemonic(KNOWN_MNEMONIC, "testnet-12", 0);
  setWalletInstance(wallet);
  return wallet;
}

function cleanupAll() {
  try { rmSync(getWalletFilePath(), { force: true }); } catch {}
  clearWalletInstance();
}

// ──────────────────────────────────────────────────────────────────────
// Subprocess-based test #1: tools/list shape (schema must have no password)
// ──────────────────────────────────────────────────────────────────────
async function testToolsListSchema() {
  const PORT = 4180;
  const TOKEN = "s".repeat(40);
  const env = {
    ...process.env,
    KASPA_ENABLE_HTTP: "1",
    KASPA_MCP_TOKEN: TOKEN,
    KASPA_ENDPOINT: "ws://127.0.0.1:1",
    PORT: String(PORT),
    KASPA_ENABLE_WALLET_SETUP: "1",
  };
  delete env.KASPA_MNEMONIC;
  delete env.KASPA_PRIVATE_KEY;
  delete env.KASPA_WALLET_PASSWORD;

  const proc = spawn("node", ["dist/index.js"], { env, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  proc.stderr.on("data", (b) => (stderr += b.toString()));

  const base = `http://127.0.0.1:${PORT}`;
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
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "x", version: "0" } },
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

  let saveTool;
  try {
    const parsed = JSON.parse(body);
    saveTool = (parsed.result?.tools ?? []).find((t) => t.name === "kaspa_save_wallet");
  } catch { /* */ }

  const props = saveTool?.inputSchema?.properties ?? {};
  const noPassword = !("password" in props);
  const noProps = Object.keys(props).length === 0;
  check(
    "tools/list: kaspa_save_wallet has empty input schema (no password arg)",
    !!saveTool && noPassword && noProps,
    `present=${!!saveTool} props=${Object.keys(props).join(",") || "(empty)"}`,
  );
}

try {
  await testToolsListSchema();

  // ────────────────────────────────────────────────────────────────────
  // 2. No active wallet
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupAll();
    const result = await saveWalletHandler({}, { envPassword: ENV_PW });
    const body = bodyOf(result);
    const ok = isErr(result) && /No active wallet/i.test(body) && !walletFileExists();
    check("no active wallet: refused, no file written", ok, body.slice(0, 120));
  }

  // ────────────────────────────────────────────────────────────────────
  // 3. Private-key-only wallet
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupAll();
    // Derive a private key from a real mnemonic, then construct a wallet
    // from the raw key (no mnemonic stored).
    const seedWallet = KaspaWallet.fromMnemonic(KNOWN_MNEMONIC, "testnet-12", 0);
    const pkHex = seedWallet.getPrivateKey().toString();
    const pkWallet = KaspaWallet.fromPrivateKey(pkHex, "testnet-12");
    setWalletInstance(pkWallet);

    const result = await saveWalletHandler({}, { envPassword: ENV_PW });
    const body = bodyOf(result);
    const ok =
      isErr(result) &&
      /private key/i.test(body) &&
      !walletFileExists() &&
      !body.includes(ENV_PW);
    check("private-key wallet: refused, no file, no env-pw leak", ok, body.slice(0, 160));
  }

  // ────────────────────────────────────────────────────────────────────
  // 4. Existing wallet file
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupAll();
    saveEncryptedWallet(KNOWN_MNEMONIC, "old-pw", "testnet-12", 0);
    activateMnemonicWallet();

    const result = await saveWalletHandler({}, { envPassword: ENV_PW });
    const body = bodyOf(result);
    const ok =
      isErr(result) &&
      /would be overwritten/i.test(body) &&
      /mv .+\.bak/.test(body) &&
      !body.includes(ENV_PW);
    check("existing file: refused, mv hint shown, no env-pw leak", ok, body.slice(0, 200));
  }

  // ────────────────────────────────────────────────────────────────────
  // 5. No password source (no env, no TTY)
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupAll();
    activateMnemonicWallet();
    const { impl } = freshTtyMock("");
    impl.isTtyAvailable = () => false;
    _setTtyImplForTests(impl);
    const result = await saveWalletHandler({}, { envPassword: undefined });
    _resetTtyImpl();
    const body = bodyOf(result);
    const ok =
      isErr(result) &&
      /No password source available/i.test(body) &&
      !walletFileExists();
    check("no password source: refused, no file", ok, body.slice(0, 160));
  }

  // ────────────────────────────────────────────────────────────────────
  // 6. Empty env password → falls through to TTY (env "" is falsy);
  //    when TTY also unavailable, refuses.
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupAll();
    activateMnemonicWallet();
    const { impl } = freshTtyMock("");
    impl.isTtyAvailable = () => false;
    _setTtyImplForTests(impl);
    const result = await saveWalletHandler({}, { envPassword: "" });
    _resetTtyImpl();
    const body = bodyOf(result);
    const ok =
      isErr(result) &&
      /No password source available/i.test(body) &&
      !walletFileExists();
    check("empty env password (no TTY): refused, no file", ok, body.slice(0, 160));
  }

  // ────────────────────────────────────────────────────────────────────
  // 7. Empty TTY password (env unset) → refused
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupAll();
    activateMnemonicWallet();
    const { impl } = freshTtyMock("");
    _setTtyImplForTests(impl);
    const result = await saveWalletHandler({}, { envPassword: undefined });
    _resetTtyImpl();
    const body = bodyOf(result);
    const ok =
      isErr(result) &&
      /Empty password/i.test(body) &&
      !walletFileExists();
    check("empty TTY password: refused, no file", ok, body.slice(0, 160));
  }

  // ────────────────────────────────────────────────────────────────────
  // 8. Env path: env set, returns success, file decrypts, source="env"
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupAll();
    const wallet = activateMnemonicWallet();
    const result = await saveWalletHandler({}, { envPassword: ENV_PW });
    const body = bodyOf(result);
    let parsed; try { parsed = JSON.parse(body); } catch { parsed = null; }

    let decryptOk = false;
    try {
      const dec = loadEncryptedWallet(ENV_PW);
      decryptOk = dec.mnemonic === KNOWN_MNEMONIC;
    } catch { /* */ }

    const ok =
      !isErr(result) &&
      parsed?.status === "saved" &&
      parsed?.passwordSource === "env" &&
      parsed?.address === wallet.getAddress() &&
      typeof parsed?.fingerprint === "string" &&
      /^[0-9a-f]{16}$/.test(parsed.fingerprint) &&
      walletFileExists() &&
      decryptOk &&
      !body.includes(ENV_PW);
    check("env path: success, file decrypts with env pw, no pw leak", ok, body.slice(0, 200));
  }

  // ────────────────────────────────────────────────────────────────────
  // 9. TTY path: env unset, TTY mock returns password → success
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupAll();
    const wallet = activateMnemonicWallet();
    const { impl } = freshTtyMock(TTY_PW);
    _setTtyImplForTests(impl);
    const result = await saveWalletHandler({}, { envPassword: undefined });
    _resetTtyImpl();
    const body = bodyOf(result);
    let parsed; try { parsed = JSON.parse(body); } catch { parsed = null; }

    let decryptOk = false;
    try {
      const dec = loadEncryptedWallet(TTY_PW);
      decryptOk = dec.mnemonic === KNOWN_MNEMONIC;
    } catch { /* */ }

    const ok =
      !isErr(result) &&
      parsed?.status === "saved" &&
      parsed?.passwordSource === "tty" &&
      parsed?.address === wallet.getAddress() &&
      walletFileExists() &&
      decryptOk &&
      !body.includes(TTY_PW);
    check("TTY path: success, file decrypts with TTY pw, no pw leak", ok, body.slice(0, 200));
  }
} finally {
  _resetTtyImpl();
  try { rmSync(TMP_HOME, { recursive: true, force: true }); } catch { /* */ }
}

const failed = results.filter((r) => !r.ok);
if (failed.length) {
  console.error(`\n${failed.length}/${results.length} checks failed`);
  process.exit(1);
}
console.log(`\nall ${results.length} checks passed`);
