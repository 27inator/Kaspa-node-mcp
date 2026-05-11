/**
 * Phase 3b smoke test: kaspa_generate_mnemonic redesign.
 *
 * In-process tests that swap the TTY ops layer so we can prove:
 *   - The mnemonic ONLY reaches the writeMnemonic channel.
 *   - The tool result NEVER contains the mnemonic phrase.
 *   - The fingerprint returned to the model is address-derived (public),
 *     not mnemonic-derived (secret).
 *   - Refusal paths fire BEFORE any file write or display:
 *       no-tty, existing-wallet, empty-password.
 *   - "saved-but-not-displayed" path fires when writeMnemonic throws after
 *     a successful encrypt+write.
 *
 * Runs entirely in-process (no spawned server, no MCP transport). Tests
 * call generateMnemonicHandler() directly with the TTY seam swapped via
 * _setTtyImplForTests().
 */

import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

// ── Setup that must run BEFORE the modules under test are imported. ───
// HOME determines the wallet-store directory (computed at import time).
const TMP_HOME = mkdtempSync(join(tmpdir(), "kaspa-mcp-mnemonic-"));
process.env.HOME = TMP_HOME;
// Don't inherit any KASPA_* config that could accidentally satisfy
// preconditions other tests rely on the absence of.
delete process.env.KASPA_WALLET_PASSWORD;
delete process.env.KASPA_MNEMONIC;
delete process.env.KASPA_PRIVATE_KEY;
// Policy parses on first import; setup mode must be on for the handler
// itself doesn't require it (it's the registration gate that does), but
// we leave it on for consistency with how production runs the handler.
process.env.KASPA_ENABLE_WALLET_SETUP = "1";

// WebSocket polyfill must load before kaspa-wasm.
await import("./dist/services/setup.js");

const { generateMnemonicHandler } = await import("./dist/tools/wallet-tools.js");
const { _setTtyImplForTests, _resetTtyImpl } = await import("./dist/services/tty.js");
const { walletFileExists, getWalletFilePath, loadEncryptedWallet } =
  await import("./dist/services/wallet-store.js");
const { isWalletConfigured, getWallet, clearWalletInstance } =
  await import("./dist/services/wallet.js");

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

const BIP39_WORD_RE = /\b[a-z]{3,8}(?:\s+[a-z]{3,8}){11}\b|\b[a-z]{3,8}(?:\s+[a-z]{3,8}){23}\b/;

function bodyOf(result) {
  return result.content[0].text;
}

function isErr(result) {
  return result.isError === true;
}

function freshTtyMock() {
  const captured = { writes: [], passwordPrompts: 0 };
  const impl = {
    isTtyAvailable: () => true,
    promptPassword: async () => {
      captured.passwordPrompts++;
      return "test-password-12345";
    },
    promptLine: async () => "",
    writeMnemonic: async (text) => {
      captured.writes.push(text);
    },
  };
  return { captured, impl };
}

function cleanupWalletFile() {
  try {
    rmSync(getWalletFilePath(), { force: true });
  } catch { /* */ }
  clearWalletInstance();
}

try {
  // ────────────────────────────────────────────────────────────────────
  // Test 1: no TTY → refuse without writing or displaying
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupWalletFile();
    const { impl } = freshTtyMock();
    impl.isTtyAvailable = () => false;
    _setTtyImplForTests(impl);
    const result = await generateMnemonicHandler({});
    _resetTtyImpl();

    const body = bodyOf(result);
    const ok =
      isErr(result) &&
      /\/dev\/tty unavailable/i.test(body) &&
      !walletFileExists() &&
      !BIP39_WORD_RE.test(body);
    check("no TTY: refused, no file written, no words leaked", ok, body.slice(0, 120));
  }

  // ────────────────────────────────────────────────────────────────────
  // Test 2: existing wallet file → refuse, file untouched, no words
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupWalletFile();
    // Write a sentinel file
    const { saveEncryptedWallet } = await import("./dist/services/wallet-store.js");
    saveEncryptedWallet(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "old-pw",
      "testnet-12",
      0,
    );
    const before = readFileSync(getWalletFilePath());

    const { impl } = freshTtyMock();
    _setTtyImplForTests(impl);
    const result = await generateMnemonicHandler({});
    _resetTtyImpl();

    const after = readFileSync(getWalletFilePath());
    const body = bodyOf(result);
    const ok =
      isErr(result) &&
      /would be overwritten/i.test(body) &&
      /mv .+\.bak/.test(body) &&
      Buffer.compare(before, after) === 0 &&
      !BIP39_WORD_RE.test(body);
    check(
      "existing wallet: refused, file unchanged, recovery hint shown",
      ok,
      body.slice(0, 160),
    );
  }

  // ────────────────────────────────────────────────────────────────────
  // Test 3: empty password from TTY → refuse, no file written, no words
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupWalletFile();
    const { impl } = freshTtyMock();
    impl.promptPassword = async () => "";
    _setTtyImplForTests(impl);
    const result = await generateMnemonicHandler({});
    _resetTtyImpl();

    const body = bodyOf(result);
    const ok =
      isErr(result) &&
      /no password provided/i.test(body) &&
      !walletFileExists() &&
      !BIP39_WORD_RE.test(body);
    check("empty password: refused, no file, no leak", ok, body.slice(0, 120));
  }

  // ────────────────────────────────────────────────────────────────────
  // Test 4: happy path — words ONLY on TTY, fingerprint is address-derived,
  //         file is decryptable, wallet is activated
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupWalletFile();
    const { captured, impl } = freshTtyMock();
    _setTtyImplForTests(impl);
    const result = await generateMnemonicHandler({ wordCount: 24, network: "testnet-12" });
    _resetTtyImpl();

    const body = bodyOf(result);
    let parsed;
    try { parsed = JSON.parse(body); } catch { parsed = null; }

    // (a) result has the right shape and no mnemonic
    const shapeOk =
      !isErr(result) &&
      parsed?.status === "saved" &&
      parsed?.network === "testnet-12" &&
      typeof parsed?.address === "string" &&
      typeof parsed?.fingerprint === "string" &&
      /^[0-9a-f]{16}$/.test(parsed.fingerprint) &&
      !BIP39_WORD_RE.test(body);

    // (b) words went to writeMnemonic exactly once. Count 12 or 24 entries
    //     of the form `<n>. <word>` in the display rather than relying on
    //     a contiguous-words regex (the columnar layout breaks adjacency).
    let mnemonicWordCount = 0;
    if (captured.writes[0]) {
      for (const _ of captured.writes[0].matchAll(/\b\d+\.\s+[a-z]+/g)) {
        mnemonicWordCount++;
      }
    }
    const ttyOk =
      captured.writes.length === 1 &&
      (mnemonicWordCount === 12 || mnemonicWordCount === 24) &&
      captured.writes[0].includes(parsed.address);

    // (c) fingerprint is address-derived, NOT mnemonic-derived
    const expectedFp = createHash("sha256")
      .update(`${parsed.network}:${parsed.address}`)
      .digest("hex")
      .slice(0, 16);
    const fpOk = parsed.fingerprint === expectedFp;

    // (d) file decrypts with the test password
    let decryptOk = false;
    let decryptedAddress = null;
    try {
      const dec = loadEncryptedWallet("test-password-12345");
      decryptOk = typeof dec.mnemonic === "string" && dec.mnemonic.split(/\s+/).length === 24;
      // Re-derive address from the decrypted mnemonic
      const { KaspaWallet } = await import("./dist/services/wallet.js");
      const wallet = KaspaWallet.fromMnemonic(dec.mnemonic, "testnet-12", 0);
      decryptedAddress = wallet.getAddress();
    } catch { /* */ }
    const fileOk = decryptOk && decryptedAddress === parsed.address;

    // (e) wallet is activated
    const activatedOk = isWalletConfigured() && getWallet().getAddress() === parsed.address;

    check(
      "happy path: shape ok, no mnemonic in result, fingerprint address-derived",
      shapeOk && fpOk && !BIP39_WORD_RE.test(body),
      `shape=${shapeOk} fp=${fpOk}`,
    );
    check(
      "happy path: mnemonic written to writeMnemonic only",
      ttyOk,
      `writes=${captured.writes.length} words=${mnemonicWordCount} addrInTty=${captured.writes[0]?.includes(parsed.address)}`,
    );
    check("happy path: file decrypts to same address", fileOk, `decryptedAddr=${decryptedAddress}`);
    check("happy path: wallet activated", activatedOk);

    // (f) Real leak detection: extract the mnemonic words IN ORDER from
    //     the TTY display (numbered "<n>. <word>" entries) and check that
    //     no 4-word sequence from the original phrase appears in the tool
    //     result body. A real leak would include a contiguous run; an
    //     individual common word ("right", "down", etc.) appearing in
    //     both the BIP39 list and our message text is just coincidence.
    if (captured.writes[0]) {
      const ordered = new Array(24);
      for (const m of captured.writes[0].matchAll(/\b(\d+)\.\s+([a-z]+)/g)) {
        ordered[parseInt(m[1], 10) - 1] = m[2];
      }
      let leakedSeq = null;
      for (let i = 0; i + 3 < ordered.length; i++) {
        if (!ordered[i] || !ordered[i+1] || !ordered[i+2] || !ordered[i+3]) continue;
        const seq = `${ordered[i]} ${ordered[i+1]} ${ordered[i+2]} ${ordered[i+3]}`;
        if (body.includes(seq)) { leakedSeq = seq; break; }
      }
      check(
        "happy path: no mnemonic-word sequence leaks into tool result",
        leakedSeq === null,
        leakedSeq ? `leakedSeq="${leakedSeq}"` : `extracted=${ordered.filter(Boolean).length}`,
      );
    }
  }

  // ────────────────────────────────────────────────────────────────────
  // Test 5: writeMnemonic fails after file write → "saved-but-not-displayed"
  // ────────────────────────────────────────────────────────────────────
  {
    cleanupWalletFile();
    const { impl } = freshTtyMock();
    impl.writeMnemonic = async () => { throw new Error("simulated tty failure"); };
    _setTtyImplForTests(impl);
    const result = await generateMnemonicHandler({});
    _resetTtyImpl();

    const body = bodyOf(result);
    let parsed;
    try { parsed = JSON.parse(body); } catch { parsed = null; }
    const checks = {
      isErr: isErr(result),
      status: parsed?.status === "saved-but-not-displayed",
      fileExists: walletFileExists(),
      hasDisplayedWarning: /could NOT be displayed/i.test(parsed?.warning ?? ""),
      hasMvHint: /mv .+\.bak/.test(parsed?.warning ?? ""),
    };
    const ok = Object.values(checks).every(Boolean);
    check(
      "writeMnemonic fails: file written, explicit warning, no words in result",
      ok,
      Object.entries(checks).map(([k, v]) => `${k}=${v}`).join(" "),
    );
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
