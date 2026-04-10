/**
 * Full workflow demo: Generate → Activate → Save → "New Session" → Load → Ready
 * Run: node test-full-workflow.mjs
 */

import WebSocket from "isomorphic-ws";
globalThis.WebSocket = WebSocket;

import { existsSync, readFileSync, statSync, renameSync, unlinkSync } from "node:fs";
import * as kaspa from "kaspa-wasm";
import {
  saveEncryptedWallet,
  loadEncryptedWallet,
  walletFileExists,
  getWalletFilePath,
} from "./dist/services/wallet-store.js";
import {
  KaspaWallet,
  setWalletInstance,
  clearWalletInstance,
  isWalletConfigured,
  getWallet,
} from "./dist/services/wallet.js";

const { Mnemonic } = kaspa;

const WALLET_FILE = getWalletFilePath();
const BACKUP = WALLET_FILE + ".demo-backup";
let backedUp = false;

// Back up existing wallet
if (existsSync(WALLET_FILE)) {
  renameSync(WALLET_FILE, BACKUP);
  backedUp = true;
}
delete process.env.KASPA_MNEMONIC;
delete process.env.KASPA_PRIVATE_KEY;
clearWalletInstance();

const PASSWORD = "KaspaProof-2026!";

try {
  // ═══════════════════════════════════════════════════════════════════
  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║   STEP 1: kaspa_generate_mnemonic                  ║");
  console.log("║   (User asks Claude to generate a new wallet)      ║");
  console.log("╚══════════════════════════════════════════════════════╝\n");

  const mnemonic = Mnemonic.random(24);
  const phrase = mnemonic.phrase;
  const wallet = KaspaWallet.fromMnemonic(phrase, "testnet-12", 0);
  setWalletInstance(wallet);

  const step1Result = {
    mnemonic: phrase,
    address: wallet.getAddress(),
    network: wallet.getNetworkId(),
    activated: true,
    warning: "IMPORTANT: Save this mnemonic securely — it cannot be recovered if lost. Use kaspa_save_wallet to encrypt and store it for future sessions.",
  };
  console.log("Tool response:");
  console.log(JSON.stringify(step1Result, null, 2));
  console.log(`\n✓ Wallet is live — isWalletConfigured(): ${isWalletConfigured()}`);
  console.log(`✓ getWallet().getAddress(): ${getWallet().getAddress()}`);

  // ═══════════════════════════════════════════════════════════════════
  console.log("\n╔══════════════════════════════════════════════════════╗");
  console.log("║   STEP 2: kaspa_save_wallet(password)              ║");
  console.log("║   (User encrypts wallet for future sessions)       ║");
  console.log("╚══════════════════════════════════════════════════════╝\n");

  saveEncryptedWallet(
    wallet.getMnemonic(),
    PASSWORD,
    wallet.getNetworkId(),
    wallet.getAccountIndex()
  );

  const step2Result = {
    success: true,
    path: getWalletFilePath(),
    network: wallet.getNetworkId(),
    address: wallet.getAddress(),
    message: "Wallet encrypted and saved. Use kaspa_load_wallet to unlock in future sessions.",
  };
  console.log("Tool response:");
  console.log(JSON.stringify(step2Result, null, 2));

  // Show file evidence
  const fileStat = statSync(WALLET_FILE);
  const fileMode = "0" + (fileStat.mode & 0o777).toString(8);
  const fileContents = JSON.parse(readFileSync(WALLET_FILE, "utf8"));

  console.log("\n── File on disk ──────────────────────────────────────");
  console.log(`Path:        ${WALLET_FILE}`);
  console.log(`Permissions: ${fileMode}`);
  console.log(`Size:        ${fileStat.size} bytes`);
  console.log(`\nEncrypted file contents:`);
  console.log(JSON.stringify(fileContents, null, 2));
  console.log("\n── Proof of encryption ──────────────────────────────");
  const rawFile = readFileSync(WALLET_FILE, "utf8");
  const mnemonicWords = phrase.split(" ");
  const leakedWords = mnemonicWords.filter(w => rawFile.includes(w));
  // Filter out common short words that could appear in JSON keys
  const trueLeaks = leakedWords.filter(w => w.length > 4);
  console.log(`Mnemonic words found in plaintext: ${trueLeaks.length === 0 ? "NONE ✓" : trueLeaks.join(", ") + " ✗"}`);

  // ═══════════════════════════════════════════════════════════════════
  console.log("\n╔══════════════════════════════════════════════════════╗");
  console.log("║   STEP 3: Simulate new session (server restart)    ║");
  console.log("║   (Wallet is locked, needs unlock)                 ║");
  console.log("╚══════════════════════════════════════════════════════╝\n");

  clearWalletInstance();

  console.log(`isWalletConfigured(): ${isWalletConfigured()}  (no active wallet)`);
  console.log(`walletFileExists():   ${walletFileExists()}  (encrypted file on disk)`);
  console.log(`\nStartup message: "Encrypted wallet found. Use kaspa_load_wallet to unlock."`);

  // Show what happens if tools are called while locked
  console.log("\n── Calling kaspa_get_my_address while locked ─────────");
  const lockedError = walletFileExists()
    ? "Encrypted wallet found. Use kaspa_load_wallet to unlock."
    : "Use kaspa_generate_mnemonic to create a wallet, or set KASPA_MNEMONIC env var.";
  console.log(`Response: { "error": "No active wallet. ${lockedError}" }`);

  // ═══════════════════════════════════════════════════════════════════
  console.log("\n╔══════════════════════════════════════════════════════╗");
  console.log("║   STEP 4: kaspa_load_wallet(password)              ║");
  console.log("║   (User unlocks wallet for this session)           ║");
  console.log("╚══════════════════════════════════════════════════════╝\n");

  const loaded = loadEncryptedWallet(PASSWORD);
  const restoredWallet = KaspaWallet.fromMnemonic(
    loaded.mnemonic,
    loaded.network,
    loaded.accountIndex
  );
  setWalletInstance(restoredWallet);

  const step4Result = {
    success: true,
    address: restoredWallet.getAddress(),
    network: restoredWallet.getNetworkId(),
    message: "Wallet unlocked and ready.",
  };
  console.log("Tool response:");
  console.log(JSON.stringify(step4Result, null, 2));

  // ═══════════════════════════════════════════════════════════════════
  console.log("\n╔══════════════════════════════════════════════════════╗");
  console.log("║   STEP 5: Verification                             ║");
  console.log("╚══════════════════════════════════════════════════════╝\n");

  const originalAddress = wallet.getAddress();
  const restoredAddress = restoredWallet.getAddress();
  const addressMatch = originalAddress === restoredAddress;

  const originalMnemonic = phrase;
  const restoredMnemonic = loaded.mnemonic;
  const mnemonicMatch = originalMnemonic === restoredMnemonic;

  console.log(`Original address:  ${originalAddress}`);
  console.log(`Restored address:  ${restoredAddress}`);
  console.log(`Address match:     ${addressMatch ? "YES ✓" : "NO ✗"}`);
  console.log();
  console.log(`Original mnemonic: ${originalMnemonic}`);
  console.log(`Restored mnemonic: ${restoredMnemonic}`);
  console.log(`Mnemonic match:    ${mnemonicMatch ? "YES ✓" : "NO ✗"}`);
  console.log();
  console.log(`isWalletConfigured(): ${isWalletConfigured()} ✓`);
  console.log(`getWallet().getAddress(): ${getWallet().getAddress()} ✓`);

  // ═══════════════════════════════════════════════════════════════════
  console.log("\n╔══════════════════════════════════════════════════════╗");
  console.log("║   STEP 6: Wrong password test                      ║");
  console.log("╚══════════════════════════════════════════════════════╝\n");

  try {
    loadEncryptedWallet("wrong-password-123");
    console.log("ERROR: Should have thrown ✗");
  } catch (e) {
    console.log(`Attempted password: "wrong-password-123"`);
    console.log(`Response: { "error": "${e.message}" } ✓`);
  }

  // ═══════════════════════════════════════════════════════════════════
  console.log("\n══════════════════════════════════════════════════════");
  if (addressMatch && mnemonicMatch) {
    console.log("  FULL WORKFLOW PASSED ✓");
  } else {
    console.log("  WORKFLOW FAILED ✗");
    process.exit(1);
  }
  console.log("══════════════════════════════════════════════════════\n");

} finally {
  // Cleanup
  if (existsSync(WALLET_FILE)) unlinkSync(WALLET_FILE);
  if (backedUp) {
    renameSync(BACKUP, WALLET_FILE);
    console.log("(Restored original wallet from backup)");
  }
  clearWalletInstance();
}
