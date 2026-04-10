/**
 * Wallet module for key management and address derivation.
 *
 * Supports BIP39 mnemonic and raw private key input.
 * Adds testnet-12 (TN12) as a valid network alongside mainnet/testnet-10/testnet-11.
 */

import * as kaspa from "kaspa-wasm";

const { PrivateKey, NetworkType, Mnemonic, XPrv } = kaspa;

export type NetworkTypeName =
  | "mainnet"
  | "testnet-10"
  | "testnet-11"
  | "testnet-12";

function getNetworkType(network: NetworkTypeName): kaspa.NetworkType {
  switch (network) {
    case "mainnet":
      return NetworkType.Mainnet;
    case "testnet-10":
    case "testnet-11":
    case "testnet-12":
      return NetworkType.Testnet;
    default:
      throw new Error(`Unsupported network: ${network}`);
  }
}

function derivePrivateKeyFromMnemonic(
  phrase: string,
  accountIndex = 0
): kaspa.PrivateKey {
  const mnemonic = new Mnemonic(phrase);
  const seed = mnemonic.toSeed();
  const xprv = new XPrv(seed);

  // BIP44 path: m/44'/111111'/account'/0/0
  // 44'      = purpose (BIP44)
  // 111111'  = Kaspa coin type
  // account' = account index (hardened)
  // 0        = external chain (receive addresses)
  // 0        = address index
  const derived = xprv
    .deriveChild(44, true)
    .deriveChild(111111, true)
    .deriveChild(accountIndex, true)
    .deriveChild(0, false)
    .deriveChild(0, false);

  return derived.toPrivateKey();
}

export class KaspaWallet {
  private privateKey: kaspa.PrivateKey;
  private keypair: kaspa.Keypair;
  private network: NetworkTypeName;

  private constructor(
    privateKey: kaspa.PrivateKey,
    network: NetworkTypeName
  ) {
    this.privateKey = privateKey;
    this.keypair = privateKey.toKeypair();
    this.network = network;
  }

  static fromPrivateKey(
    privateKeyHex: string,
    network: NetworkTypeName = "testnet-12"
  ): KaspaWallet {
    if (!privateKeyHex) throw new Error("Private key is required");
    const privateKey = new PrivateKey(privateKeyHex);
    return new KaspaWallet(privateKey, network);
  }

  static fromMnemonic(
    phrase: string,
    network: NetworkTypeName = "testnet-12",
    accountIndex = 0
  ): KaspaWallet {
    if (!phrase) throw new Error("Mnemonic phrase is required");
    const privateKey = derivePrivateKeyFromMnemonic(phrase, accountIndex);
    return new KaspaWallet(privateKey, network);
  }

  getAddress(): string {
    return this.keypair.toAddress(getNetworkType(this.network)).toString();
  }

  getPrivateKey(): kaspa.PrivateKey {
    return this.privateKey;
  }

  getNetworkType(): kaspa.NetworkType {
    return getNetworkType(this.network);
  }

  getNetworkId(): string {
    return this.network;
  }
}

// ── Singleton ──────────────────────────────────────────────────────────

let walletInstance: KaspaWallet | null = null;

const VALID_NETWORKS: NetworkTypeName[] = [
  "mainnet",
  "testnet-10",
  "testnet-11",
  "testnet-12",
];

/**
 * Get or create the wallet singleton from environment variables.
 * Throws if neither KASPA_MNEMONIC nor KASPA_PRIVATE_KEY is set.
 */
export function getWallet(): KaspaWallet {
  if (!walletInstance) {
    const mnemonic = process.env.KASPA_MNEMONIC;
    const privateKey = process.env.KASPA_PRIVATE_KEY;
    const networkEnv = process.env.KASPA_NETWORK || "testnet-12";

    if (!VALID_NETWORKS.includes(networkEnv as NetworkTypeName)) {
      throw new Error(
        `Invalid KASPA_NETWORK: "${networkEnv}". Supported: ${VALID_NETWORKS.join(", ")}`
      );
    }
    const network = networkEnv as NetworkTypeName;

    const accountIndexStr = process.env.KASPA_ACCOUNT_INDEX || "0";
    const accountIndex = parseInt(accountIndexStr, 10);
    if (isNaN(accountIndex) || accountIndex < 0) {
      throw new Error(
        `Invalid KASPA_ACCOUNT_INDEX: "${accountIndexStr}". Must be a non-negative integer.`
      );
    }

    if (mnemonic) {
      walletInstance = KaspaWallet.fromMnemonic(mnemonic, network, accountIndex);
    } else if (privateKey) {
      walletInstance = KaspaWallet.fromPrivateKey(privateKey, network);
    } else {
      throw new Error(
        "Either KASPA_MNEMONIC or KASPA_PRIVATE_KEY environment variable must be set for wallet operations"
      );
    }
  }
  return walletInstance;
}

/** Check if wallet credentials are configured (without throwing). */
export function isWalletConfigured(): boolean {
  return !!(process.env.KASPA_MNEMONIC || process.env.KASPA_PRIVATE_KEY || walletInstance);
}

/**
 * Reset the wallet singleton so it can be re-initialized.
 * Used when activating a newly generated or loaded wallet at runtime.
 */
export function resetWallet(): void {
  walletInstance = null;
}

/**
 * Activate a wallet from a mnemonic at runtime (no env var needed).
 * Sets the mnemonic in process.env and re-initializes the singleton.
 */
export function activateWallet(
  mnemonic: string,
  network?: NetworkTypeName,
  accountIndex?: number
): KaspaWallet {
  process.env.KASPA_MNEMONIC = mnemonic;
  if (network) {
    process.env.KASPA_NETWORK = network;
  }
  if (accountIndex !== undefined) {
    process.env.KASPA_ACCOUNT_INDEX = String(accountIndex);
  }
  walletInstance = null;
  return getWallet();
}
