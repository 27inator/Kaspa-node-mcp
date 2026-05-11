/**
 * Startup wallet unlock.
 *
 * Replaces the old `kaspa_load_wallet(password)` tool. Decrypts the
 * encrypted wallet file at startup using one of two password sources.
 *
 * Order: KASPA_WALLET_PASSWORD env (when set) → /dev/tty prompt.
 *
 * Rationale: setting the env var is a stronger explicit signal than "/dev/
 * tty happens to be available" — operators who set it almost always want
 * headless automation and don't want to wait 60s for a TTY prompt to time
 * out before the env is consulted. When env is unset, we fall back to TTY
 * for interactive launches.
 *
 * Threat-model note on env: KASPA_WALLET_PASSWORD can leak through shell
 * history, launch configs, crash reports, and process inspection. The TTY
 * path keeps the password out of process env and out of the MCP transcript
 * — prefer it for any interactive setup. README documents both clearly.
 *
 * This function is fire-and-forget. It must be called AFTER `server.connect()`
 * so a stuck prompt cannot freeze the MCP handshake. If unlock fails for
 * any reason (no source, wrong password, timeout, no encrypted file), the
 * server keeps running in a wallet-locked state and signing/setup tools
 * surface a clear error on first call.
 *
 * Gates:
 *   - Skipped entirely unless KASPA_ENABLE_SIGNING=1 or
 *     KASPA_ENABLE_WALLET_SETUP=1. Read-only servers never prompt.
 *   - Skipped if KASPA_MNEMONIC / KASPA_PRIVATE_KEY is already configured.
 *   - Skipped if no encrypted wallet file exists.
 *
 * Test affordance: KASPA_WALLET_UNLOCK_TIMEOUT_MS overrides the default 60s
 * TTY prompt timeout. Documented for test harnesses; not part of the public
 * API surface.
 */

import { policy } from "./policy.js";
import { walletFileExists, loadEncryptedWallet } from "./wallet-store.js";
import {
  isWalletConfigured,
  setWalletInstance,
  KaspaWallet,
  type NetworkTypeName,
} from "./wallet.js";
import {
  promptPassword,
  isTtyAvailable,
  PromptTimeoutError,
} from "./tty.js";
import { audit } from "./audit.js";

let unlockTimeoutWarningEmitted = false;

function unlockTimeoutMs(): number {
  const raw = process.env.KASPA_WALLET_UNLOCK_TIMEOUT_MS;
  if (!raw) return 60_000;
  if (!/^\d+$/.test(raw)) return 60_000;
  const v = Number(raw);
  if (!(v > 0 && Number.isFinite(v))) return 60_000;
  // Loud warning when active — matches the test-only-env documentation in
  // the README. Emitted once per process; idempotent across repeated calls.
  if (!unlockTimeoutWarningEmitted) {
    unlockTimeoutWarningEmitted = true;
    console.error(
      `[kaspa-mcp] *** KASPA_WALLET_UNLOCK_TIMEOUT_MS=${v} — TTY unlock ` +
        `timeout is OVERRIDDEN from the 60s default. This is a test-only ` +
        `knob; never set in production. ***`,
    );
  }
  return v;
}

let unlockAttempted = false;

/**
 * Run the startup unlock dance. Idempotent — repeat calls are no-ops.
 *
 * Always resolves; never throws. Failures are logged to stderr so the
 * operator sees them in MCP server logs.
 */
export async function tryStartupUnlock(): Promise<void> {
  if (unlockAttempted) return;
  unlockAttempted = true;

  // Fast paths first — none of these involve a prompt.
  if (isWalletConfigured()) {
    return; // env mnemonic / private key already populated the wallet
  }
  if (!walletFileExists()) {
    return; // nothing to unlock
  }
  if (!policy.enableSigning && !policy.enableWalletSetup) {
    // Read-only mode: don't surprise the operator with a password prompt.
    return;
  }

  console.error("[kaspa-mcp] Encrypted wallet found. Attempting startup unlock.");

  // Env first when set — explicit headless signal. Falls through on
  // mismatch so an interactive operator can still try TTY.
  if (policy.walletPasswordEnv) {
    console.error(
      "[kaspa-mcp] Trying KASPA_WALLET_PASSWORD env. " +
        "Note: env vars can leak via shell history / process inspection — " +
        "prefer TTY for interactive setups."
    );
    if (await tryDecrypt(policy.walletPasswordEnv, "KASPA_WALLET_PASSWORD env")) return;
    console.error("[kaspa-mcp] KASPA_WALLET_PASSWORD did not decrypt the wallet. Falling through.");
  }

  // TTY for interactive launches.
  if (isTtyAvailable()) {
    const timeoutMs = unlockTimeoutMs();
    console.error("[kaspa-mcp] Prompting for wallet password on /dev/tty.");
    console.error(
      `[kaspa-mcp] If you don't see a prompt, set KASPA_WALLET_PASSWORD ` +
        `or restart from a terminal. Timeout: ${timeoutMs / 1000}s.`
    );
    try {
      const password = await promptPassword("Wallet password: ", { timeoutMs });
      if (await tryDecrypt(password, "TTY prompt")) return;
      console.error("[kaspa-mcp] Incorrect password from TTY prompt.");
    } catch (e) {
      if (e instanceof PromptTimeoutError) {
        console.error(`[kaspa-mcp] TTY prompt: ${e.message}.`);
      } else {
        console.error(
          `[kaspa-mcp] TTY prompt failed: ${e instanceof Error ? e.message : String(e)}.`
        );
      }
    }
  } else if (!policy.walletPasswordEnv) {
    console.error(
      "[kaspa-mcp] No /dev/tty available and no KASPA_WALLET_PASSWORD set."
    );
  }

  console.error(
    "[kaspa-mcp] Wallet remains locked. Signing/setup tools will fail with a " +
      "clear error until the server is restarted with a working unlock path."
  );
}

async function tryDecrypt(password: string, source: string): Promise<boolean> {
  try {
    const { mnemonic, network, accountIndex } = loadEncryptedWallet(password);
    const wallet = KaspaWallet.fromMnemonic(
      mnemonic,
      network as NetworkTypeName,
      accountIndex
    );
    setWalletInstance(wallet);
    console.error(
      `[kaspa-mcp] Wallet unlocked via ${source}: ${wallet.getAddress()} ` +
        `(${wallet.getNetworkId()})`
    );
    audit("wallet_unlocked", {
      // Map "TTY prompt" / "KASPA_WALLET_PASSWORD env" → short forensic tag.
      source: source.includes("env") ? "env" : "tty",
      network: wallet.getNetworkId(),
      address: wallet.getAddress(),
    });
    return true;
  } catch {
    return false;
  }
}

/** For tests: reset the once-only guard so a fresh unlock can be attempted. */
export function _resetUnlockState(): void {
  unlockAttempted = false;
}
