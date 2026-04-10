/**
 * Encrypted wallet file storage.
 *
 * Saves and loads wallet mnemonic encrypted with AES-256-GCM.
 * Key derived via scrypt. Stored at ~/.kaspa-mcp/wallet.enc (chmod 600).
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  chmodSync,
} from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const WALLET_DIR = join(homedir(), ".kaspa-mcp");
const WALLET_FILE = join(WALLET_DIR, "wallet.enc");

// scrypt: N=2^16, r=8, p=1 (~64 MiB memory, ~200ms on modern hardware)
const SCRYPT_N = 65536;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32; // AES-256
const SALT_LEN = 16;
const IV_LEN = 12; // GCM standard

interface WalletFile {
  version: 1;
  kdf: "scrypt";
  kdfParams: { N: number; r: number; p: number };
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
  network: string;
  accountIndex: number;
}

function deriveKey(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 128 * 1024 * 1024,
  });
}

export function walletFileExists(): boolean {
  return existsSync(WALLET_FILE);
}

export function getWalletFilePath(): string {
  return WALLET_FILE;
}

export function saveEncryptedWallet(
  mnemonic: string,
  password: string,
  network: string,
  accountIndex: number
): void {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = deriveKey(password, salt);

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(mnemonic, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  const data: WalletFile = {
    version: 1,
    kdf: "scrypt",
    kdfParams: { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: encrypted.toString("base64"),
    network,
    accountIndex,
  };

  if (!existsSync(WALLET_DIR)) {
    mkdirSync(WALLET_DIR, { mode: 0o700 });
  }

  writeFileSync(WALLET_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
  chmodSync(WALLET_FILE, 0o600);
}

export interface DecryptedWallet {
  mnemonic: string;
  network: string;
  accountIndex: number;
}

export function loadEncryptedWallet(password: string): DecryptedWallet {
  if (!walletFileExists()) {
    throw new Error(
      `No wallet file found at ${WALLET_FILE}. Use kaspa_generate_mnemonic + kaspa_save_wallet first.`
    );
  }

  const raw = readFileSync(WALLET_FILE, "utf8");
  const data: WalletFile = JSON.parse(raw);

  if (data.version !== 1) {
    throw new Error(`Unsupported wallet file version: ${data.version}`);
  }

  const salt = Buffer.from(data.salt, "base64");
  const iv = Buffer.from(data.iv, "base64");
  const authTag = Buffer.from(data.authTag, "base64");
  const ciphertext = Buffer.from(data.ciphertext, "base64");
  const key = deriveKey(password, salt);

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  try {
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return {
      mnemonic: plaintext.toString("utf8"),
      network: data.network,
      accountIndex: data.accountIndex,
    };
  } catch {
    throw new Error("Incorrect password or corrupted wallet file.");
  }
}
