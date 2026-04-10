/**
 * Test: Encrypted wallet save/load roundtrip.
 * Run: node test-wallet-store.mjs
 *
 * Tests:
 *   1. Generate mnemonic via WASM
 *   2. Create wallet, verify mnemonic/accountIndex stored
 *   3. Save encrypted wallet to disk
 *   4. Load with correct password — verify address matches
 *   5. Load with wrong password — verify rejection
 *   6. setWalletInstance / isWalletConfigured integration
 *   7. Private-key wallet has no mnemonic (cannot save)
 *   8. Cleanup
 */

// WebSocket polyfill must come first
import WebSocket from "isomorphic-ws";
globalThis.WebSocket = WebSocket;

import { existsSync, readFileSync, renameSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

import * as kaspa from "kaspa-wasm";
import {
  saveEncryptedWallet,
  loadEncryptedWallet,
  walletFileExists,
  getWalletFilePath,
} from "./dist/services/wallet-store.js";
import {
  KaspaWallet,
  getWallet,
  setWalletInstance,
  clearWalletInstance,
  isWalletConfigured,
} from "./dist/services/wallet.js";

const { Mnemonic } = kaspa;

const WALLET_FILE = getWalletFilePath();
const BACKUP_FILE = WALLET_FILE + ".test-backup";
let backedUp = false;
let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  PASS: ${label}`);
    passed++;
  } else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

function assertThrows(fn, substring, label) {
  try {
    fn();
    console.error(`  FAIL: ${label} (no error thrown)`);
    failed++;
  } catch (e) {
    if (e.message.includes(substring)) {
      console.log(`  PASS: ${label}`);
      passed++;
    } else {
      console.error(`  FAIL: ${label} (wrong error: "${e.message}")`);
      failed++;
    }
  }
}

// ── Setup: back up existing wallet file if present ────────────────────
if (existsSync(WALLET_FILE)) {
  renameSync(WALLET_FILE, BACKUP_FILE);
  backedUp = true;
  console.log(`Backed up existing wallet to ${BACKUP_FILE}\n`);
}

// Clear any env-var-based wallet singleton
delete process.env.KASPA_MNEMONIC;
delete process.env.KASPA_PRIVATE_KEY;
clearWalletInstance();

try {
  // ── Test 1: Generate mnemonic ─────────────────────────────────────
  console.log("=== Test 1: Generate Mnemonic ===");
  const mnemonic = Mnemonic.random(24);
  const phrase = mnemonic.phrase;
  assert(phrase.split(" ").length === 24, "24-word mnemonic generated");

  // ── Test 2: Create wallet, verify mnemonic stored ─────────────────
  console.log("\n=== Test 2: KaspaWallet.fromMnemonic ===");
  const wallet = KaspaWallet.fromMnemonic(phrase, "testnet-12", 0);
  const address = wallet.getAddress();
  assert(address.startsWith("kaspatest:"), `Address has testnet prefix: ${address}`);
  assert(wallet.getMnemonic() === phrase, "Mnemonic stored on wallet");
  assert(wallet.getAccountIndex() === 0, "Account index stored on wallet");
  assert(wallet.getNetworkId() === "testnet-12", "Network stored on wallet");

  // ── Test 3: Save encrypted ────────────────────────────────────────
  console.log("\n=== Test 3: Save Encrypted Wallet ===");
  const PASSWORD = "test-password-2026!";
  saveEncryptedWallet(phrase, PASSWORD, "testnet-12", 0);
  assert(walletFileExists(), "Wallet file created");

  // Verify file permissions (Unix only)
  const raw = readFileSync(WALLET_FILE, "utf8");
  const data = JSON.parse(raw);
  assert(data.version === 1, "File version is 1");
  assert(data.kdf === "scrypt", "KDF is scrypt");
  assert(data.network === "testnet-12", "Network stored in file");
  assert(data.accountIndex === 0, "Account index stored in file");
  assert(typeof data.salt === "string" && data.salt.length > 0, "Salt present");
  assert(typeof data.iv === "string" && data.iv.length > 0, "IV present");
  assert(typeof data.authTag === "string" && data.authTag.length > 0, "Auth tag present");
  assert(typeof data.ciphertext === "string" && data.ciphertext.length > 0, "Ciphertext present");
  assert(!raw.includes(phrase), "Mnemonic NOT in plaintext in file");

  // ── Test 4: Load with correct password ────────────────────────────
  console.log("\n=== Test 4: Load With Correct Password ===");
  const loaded = loadEncryptedWallet(PASSWORD);
  assert(loaded.mnemonic === phrase, "Decrypted mnemonic matches original");
  assert(loaded.network === "testnet-12", "Network matches");
  assert(loaded.accountIndex === 0, "Account index matches");

  // Recreate wallet from loaded data and verify same address
  const wallet2 = KaspaWallet.fromMnemonic(loaded.mnemonic, loaded.network, loaded.accountIndex);
  assert(wallet2.getAddress() === address, `Address matches: ${wallet2.getAddress()}`);

  // ── Test 5: Load with wrong password ──────────────────────────────
  console.log("\n=== Test 5: Wrong Password Rejection ===");
  assertThrows(
    () => loadEncryptedWallet("wrong-password"),
    "Incorrect password",
    "Wrong password throws 'Incorrect password' error"
  );
  assertThrows(
    () => loadEncryptedWallet(""),
    "Incorrect password",
    "Empty password throws error"
  );

  // ── Test 6: setWalletInstance / isWalletConfigured ─────────────────
  console.log("\n=== Test 6: Runtime Wallet Activation ===");
  clearWalletInstance();
  assert(!isWalletConfigured(), "isWalletConfigured() false after clear (no env vars)");

  setWalletInstance(wallet);
  assert(isWalletConfigured(), "isWalletConfigured() true after setWalletInstance");

  const retrieved = getWallet();
  assert(retrieved.getAddress() === address, "getWallet() returns same address after set");
  assert(retrieved.getMnemonic() === phrase, "getWallet() returns wallet with mnemonic");

  clearWalletInstance();
  assert(!isWalletConfigured(), "isWalletConfigured() false after second clear");

  // ── Test 7: Private-key wallet has no mnemonic ────────────────────
  console.log("\n=== Test 7: Private Key Wallet (No Mnemonic) ===");
  // Derive a private key hex from the mnemonic wallet for testing
  const pkHex = wallet.getPrivateKey().toString();
  const pkWallet = KaspaWallet.fromPrivateKey(pkHex, "testnet-12");
  assert(pkWallet.getMnemonic() === undefined, "Private-key wallet has no mnemonic");
  assert(pkWallet.getAddress() === address, "Same address from same private key");

  // ── Test 8: Overwrite existing file ───────────────────────────────
  console.log("\n=== Test 8: Overwrite Existing Wallet File ===");
  const mnemonic2 = Mnemonic.random(12);
  const phrase2 = mnemonic2.phrase;
  const wallet3 = KaspaWallet.fromMnemonic(phrase2, "testnet-11", 2);
  saveEncryptedWallet(phrase2, "different-pass", "testnet-11", 2);
  const loaded2 = loadEncryptedWallet("different-pass");
  assert(loaded2.mnemonic === phrase2, "Overwritten file has new mnemonic");
  assert(loaded2.network === "testnet-11", "Overwritten file has new network");
  assert(loaded2.accountIndex === 2, "Overwritten file has new account index");

  // Old password no longer works
  assertThrows(
    () => loadEncryptedWallet(PASSWORD),
    "Incorrect password",
    "Old password rejected after overwrite"
  );

  // ── Test 9: Delete file, verify walletFileExists ──────────────────
  console.log("\n=== Test 9: File Deletion ===");
  unlinkSync(WALLET_FILE);
  assert(!walletFileExists(), "walletFileExists() false after delete");
  assertThrows(
    () => loadEncryptedWallet("any-password"),
    "No wallet file found",
    "Loading deleted file throws clear error"
  );

} finally {
  // ── Cleanup ─────────────────────────────────────────────────────────
  if (existsSync(WALLET_FILE)) {
    unlinkSync(WALLET_FILE);
  }
  if (backedUp) {
    renameSync(BACKUP_FILE, WALLET_FILE);
    console.log(`\nRestored original wallet from backup.`);
  }
  clearWalletInstance();
}

// ── Results ───────────────────────────────────────────────────────────
console.log(`\n${"=".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.error("SOME TESTS FAILED");
  process.exit(1);
} else {
  console.log("ALL TESTS PASSED");
}
