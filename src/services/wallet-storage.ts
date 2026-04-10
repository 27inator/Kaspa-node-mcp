/**
 * Encrypted wallet file storage using AES-256-GCM.
 *
 * Persists wallet mnemonic to ~/.kaspa-mcp/wallet.enc so users don't need
 * to manually configure environment variables across sessions.
 */

import { randomBytes, createCipheriv, createDecipheriv, scryptSync } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const WALLET_DIR = join(homedir(), ".kaspa-mcp");
const WALLET_FILE = join(WALLET_DIR, "wallet.enc");

const ALGORITHM = "aes-256-gcm";
const SALT_BYTES = 32;
const IV_BYTES = 16;
const TAG_BYTES = 16;
const KEY_LENGTH = 32;
const SCRYPT_COST = 16384;

interface WalletData {
  mnemonic: string;
  network: string;
  accountIndex: number;
}

function deriveKey(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, KEY_LENGTH, { N: SCRYPT_COST }) as Buffer;
}

/**
 * Encrypt and save wallet data to ~/.kaspa-mcp/wallet.enc.
 * File permissions are set to owner-only (0600).
 */
export function saveEncryptedWallet(
  data: WalletData,
  password: string
): string {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = deriveKey(password, salt);

  const cipher = createCipheriv(ALGORITHM, key, iv);
  const plaintext = JSON.stringify(data);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  // Format: salt (32) + iv (16) + tag (16) + ciphertext
  const output = Buffer.concat([salt, iv, tag, encrypted]);

  if (!existsSync(WALLET_DIR)) {
    mkdirSync(WALLET_DIR, { recursive: true, mode: 0o700 });
  }

  writeFileSync(WALLET_FILE, output);
  chmodSync(WALLET_FILE, 0o600);

  return WALLET_FILE;
}

/**
 * Load and decrypt wallet data from ~/.kaspa-mcp/wallet.enc.
 * Throws if the file doesn't exist, password is wrong, or data is corrupt.
 */
export function loadEncryptedWallet(password: string): WalletData {
  if (!existsSync(WALLET_FILE)) {
    throw new Error(
      `No saved wallet found at ${WALLET_FILE}. Generate one first with kaspa_generate_mnemonic.`
    );
  }

  const raw = readFileSync(WALLET_FILE);
  if (raw.length < SALT_BYTES + IV_BYTES + TAG_BYTES + 1) {
    throw new Error("Wallet file is corrupt or truncated.");
  }

  const salt = raw.subarray(0, SALT_BYTES);
  const iv = raw.subarray(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const tag = raw.subarray(SALT_BYTES + IV_BYTES, SALT_BYTES + IV_BYTES + TAG_BYTES);
  const ciphertext = raw.subarray(SALT_BYTES + IV_BYTES + TAG_BYTES);

  const key = deriveKey(password, salt);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted: string;
  try {
    decrypted = decipher.update(ciphertext) + decipher.final("utf8");
  } catch {
    throw new Error("Incorrect password or corrupt wallet file.");
  }

  return JSON.parse(decrypted) as WalletData;
}

/** Check whether a saved wallet file exists. */
export function hasSavedWallet(): boolean {
  return existsSync(WALLET_FILE);
}

/** Get the wallet file path. */
export function getWalletFilePath(): string {
  return WALLET_FILE;
}
