/**
 * Terminal prompts via /dev/tty.
 *
 * Used for two purposes:
 *   1. Wallet password prompt at startup (echo off).
 *   2. Per-transaction confirmation phrase (echo on, Phase 3).
 *
 * Implementation note: prompts run in a child `sh -c` process rather than
 * via Node's `readSync` so the parent's event loop stays responsive while
 * the user types. This matters because:
 *   - The MCP stdio transport already owns Node's stdin/stdout, so we have
 *     to read from /dev/tty directly.
 *   - readSync against /dev/tty blocks the entire Node event loop, which
 *     would freeze MCP request processing during the prompt.
 *
 * The shell snippet handles the `stty -echo` / restore dance with a `trap`
 * so a SIGINT / SIGTERM during the prompt always restores normal echo
 * behavior on the user's terminal.
 */

import { spawn } from "node:child_process";
import { closeSync, openSync, writeSync } from "node:fs";

export class TtyUnavailableError extends Error {
  constructor(reason: string) {
    super(`/dev/tty unavailable: ${reason}`);
    this.name = "TtyUnavailableError";
  }
}

export class PromptTimeoutError extends Error {
  constructor(ms: number) {
    super(`prompt timed out after ${ms}ms`);
    this.name = "PromptTimeoutError";
  }
}

export class PromptAbortedError extends Error {
  constructor() {
    super("prompt aborted");
    this.name = "PromptAbortedError";
  }
}

/**
 * True if /dev/tty is openable in the current process. Used to gate
 * elicitation/TTY/refuse fallback chains without raising.
 */
export function isTtyAvailable(): boolean {
  try {
    const fd = openSync("/dev/tty", "r+");
    closeSync(fd);
    return true;
  } catch {
    return false;
  }
}

export interface PromptOptions {
  /** Hard timeout in ms. Set <=0 or omit to disable. */
  timeoutMs?: number;
  /** Abort the prompt when this signal fires. */
  signal?: AbortSignal;
}

// Echo-off variant. Captures the user's exact prior terminal mode with
// `stty -g`, sets `-echo` for the read, and restores the saved mode on every
// exit path (normal, INT, TERM, error).
//
// Signal trap subtlety: a bare `trap 'restore' EXIT INT TERM` would catch
// SIGINT/SIGTERM, run the restore, and then let the read-interrupted shell
// fall through to the final `printf '%s' "$REPLY"` — the parent would see
// exit code 0 and a successful EMPTY password. To prevent that, the signal
// traps explicitly exit with conventional 128+signal codes (130 = SIGINT,
// 143 = SIGTERM); EXIT only restores. The parent's child-close handler
// rejects on any non-zero code, so kill/Ctrl-C cannot turn into a silent
// empty-string success.
const PROMPT_SCRIPT_ECHO_OFF =
  // $1 holds the prompt text; passing as positional arg avoids shell-quoting
  // hazards and any chance of injection from prompt content.
  `saved=$(stty -g </dev/tty) || { echo "stty -g failed" >&2; exit 2; }; ` +
  `trap 'stty "$saved" </dev/tty 2>/dev/null' EXIT; ` +
  `trap 'stty "$saved" </dev/tty 2>/dev/null; exit 130' INT; ` +
  `trap 'stty "$saved" </dev/tty 2>/dev/null; exit 143' TERM; ` +
  `printf '%s' "$1" >/dev/tty; ` +
  `stty -echo </dev/tty; ` +
  `IFS= read -r REPLY </dev/tty || exit 1; ` +
  // Explicit success-path restore (EXIT trap also runs, but doing it here
  // keeps behavior obvious if the trap is ever altered).
  `stty "$saved" </dev/tty; ` +
  // User-facing newline AFTER the restore so the cursor advance happens
  // with normal echo.
  `printf '\\n' >/dev/tty; ` +
  // Captured by parent over the child's stdout pipe.
  `printf '%s' "$REPLY"`;

// Echo-on variant. No mode change → no restore needed. We do not capture
// $(stty -g) here because making the read fail-closed against transient
// stty failures would worsen UX without security benefit.
const PROMPT_SCRIPT_ECHO_ON =
  `printf '%s' "$1" >/dev/tty; ` +
  `IFS= read -r REPLY </dev/tty; ` +
  `printf '%s' "$REPLY"`;

async function runChildPrompt(
  prompt: string,
  echoOff: boolean,
  opts: PromptOptions
): Promise<string> {
  if (!isTtyAvailable()) {
    throw new TtyUnavailableError("could not open /dev/tty");
  }
  const script = echoOff ? PROMPT_SCRIPT_ECHO_OFF : PROMPT_SCRIPT_ECHO_ON;

  return new Promise<string>((resolve, reject) => {
    const child = spawn("sh", ["-c", script, "kaspa-mcp-prompt", prompt], {
      // Child inherits no stdin (it reads from /dev/tty directly), captures
      // stdout (the response), inherits stderr so any shell error prints
      // to the operator's logs.
      stdio: ["ignore", "pipe", "inherit"],
    });

    let stdout = "";
    child.stdout.on("data", (b) => (stdout += b.toString("utf8")));

    let timer: NodeJS.Timeout | undefined;
    let settled = false;

    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", onAbort);
      fn();
    };

    const onAbort = () => {
      try { child.kill("SIGTERM"); } catch { /* noop */ }
      settle(() => reject(new PromptAbortedError()));
    };
    if (opts.signal) {
      if (opts.signal.aborted) {
        try { child.kill("SIGTERM"); } catch { /* noop */ }
        return reject(new PromptAbortedError());
      }
      opts.signal.addEventListener("abort", onAbort);
    }

    if (opts.timeoutMs && opts.timeoutMs > 0) {
      timer = setTimeout(() => {
        try { child.kill("SIGTERM"); } catch { /* noop */ }
        settle(() => reject(new PromptTimeoutError(opts.timeoutMs!)));
      }, opts.timeoutMs);
    }

    child.on("error", (e) => settle(() => reject(e)));
    child.on("close", (code) => {
      if (code === 0) {
        settle(() => resolve(stdout));
      } else {
        settle(() => reject(new Error(`prompt exited with code ${code}`)));
      }
    });
  });
}

/** Async password prompt with echo disabled. Returns the line the user typed. */
export function promptPassword(
  prompt: string,
  opts: PromptOptions = {}
): Promise<string> {
  return runChildPrompt(prompt, /*echoOff*/ true, opts);
}

/** Async line prompt with echo enabled (used for Phase 3 confirmation phrase). */
export function promptLine(
  prompt: string,
  opts: PromptOptions = {}
): Promise<string> {
  return runChildPrompt(prompt, /*echoOff*/ false, opts);
}

/**
 * One-shot write to /dev/tty. Used to display the mnemonic in 3b — that
 * value must reach a channel the model cannot observe, and stderr is
 * unsafe because Claude Code surfaces stderr in the MCP-server log panel.
 *
 * Synchronous because the write is small (a few hundred bytes) and any
 * meaningful blocking would mean /dev/tty is broken anyway, in which case
 * we want the openSync to fail loudly.
 */
export async function writeToTty(text: string): Promise<void> {
  let fd: number;
  try {
    fd = openSync("/dev/tty", "w");
  } catch (e) {
    throw new TtyUnavailableError(
      e instanceof Error ? e.message : String(e)
    );
  }
  try {
    writeSync(fd, text);
  } finally {
    try { closeSync(fd); } catch { /* noop */ }
  }
}

// ── Test seam ─────────────────────────────────────────────────────────
//
// Production callers should use `tty.<op>(...)` (the namespace below)
// rather than the bare exports above. The namespace dispatches through a
// mutable `active` impl so tests can swap individual operations without
// touching the real /dev/tty.
//
// Why a namespace plus bare exports: the bare exports keep wallet-unlock
// (Phase 2, already shipped) working without a refactor; new callers
// (Phase 3b mnemonic handler, Phase 3e confirmations) use the namespace
// so their tests can inject canned responses for promptPassword /
// promptLine and capture writeMnemonic output.

export interface TtyOps {
  isTtyAvailable(): boolean;
  promptPassword(prompt: string, opts?: PromptOptions): Promise<string>;
  promptLine(prompt: string, opts?: PromptOptions): Promise<string>;
  writeMnemonic(text: string): Promise<void>;
}

const realImpl: TtyOps = {
  isTtyAvailable,
  promptPassword,
  promptLine,
  writeMnemonic: writeToTty,
};

let active: TtyOps = realImpl;

export const tty: TtyOps = {
  isTtyAvailable: () => active.isTtyAvailable(),
  promptPassword: (p, o) => active.promptPassword(p, o),
  promptLine: (p, o) => active.promptLine(p, o),
  writeMnemonic: (t) => active.writeMnemonic(t),
};

/**
 * Test-only: replace any subset of TTY ops with mocks. Unspecified ops
 * fall back to the real implementation. Always pair with _resetTtyImpl()
 * in a `finally` so subsequent tests see the real impl.
 */
export function _setTtyImplForTests(impl: Partial<TtyOps>): void {
  active = { ...realImpl, ...impl };
}

/** Test-only: restore the production TTY impl. */
export function _resetTtyImpl(): void {
  active = realImpl;
}
