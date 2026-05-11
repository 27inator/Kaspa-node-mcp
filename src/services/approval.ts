/**
 * Confirmation approval resolver.
 *
 * The two-step send flow's job is to make sure the model alone cannot
 * authorize a broadcast. The token map gives single-use semantics; this
 * module provides the actual out-of-band approval channel.
 *
 * Order:
 *   1. Try MCP elicitation (`elicitInput`) — sends an `elicitation/create`
 *      request the CLIENT renders to the user. The model never sees the
 *      response. This is the strongest, cleanest path when the client
 *      supports it (Claude Code, modern MCP clients).
 *   2. Fall back to /dev/tty: prompt the operator to type
 *      `APPROVE <digest>` exactly. The model cannot synthesize the typed
 *      input; tty is read in a child process.
 *   3. If neither channel is available, refuse — better to fail loudly
 *      than to broadcast on a model-only signal.
 *
 * The capability probe is "try and see": elicitInput is called; any error
 * (unsupported client, network, schema validation) is treated as
 * unsupported and we fall through. This is more robust than a synchronous
 * capability check and matches the reviewer's guidance.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { tty } from "./tty.js";

export type ApprovalResult =
  | { approved: true; method: "elicitation" | "tty" }
  | { approved: false; reason: "declined" | "tty_mismatch" | "tty_failed" | "no_channel" };

export interface ApprovalChannel {
  /**
   * Attempt MCP elicitation. Resolve to {approved} on a clean
   * accept/decline; resolve to "unsupported" on any error (the elicit
   * call threw, the client said it doesn't support it, schema mismatch,
   * etc.). Never throws.
   */
  tryElicit(message: string, digest: string): Promise<{ approved: boolean } | "unsupported">;
  isTtyAvailable(): boolean;
  /** Reads a line from /dev/tty with echo on. Throws on TTY failure / timeout. */
  promptTty(prompt: string, timeoutMs: number): Promise<string>;
}

const TTY_TIMEOUT_MS = 60_000;

export async function resolveApproval(
  channel: ApprovalChannel,
  preview: string,
  digest: string,
): Promise<ApprovalResult> {
  // 1. Elicitation first.
  const elicit = await channel.tryElicit(preview, digest);
  if (elicit !== "unsupported") {
    return elicit.approved
      ? { approved: true, method: "elicitation" }
      : { approved: false, reason: "declined" };
  }

  // 2. TTY fallback.
  if (!channel.isTtyAvailable()) {
    return { approved: false, reason: "no_channel" };
  }

  let line: string;
  try {
    line = await channel.promptTty(
      `Type APPROVE ${digest} to send: `,
      TTY_TIMEOUT_MS,
    );
  } catch {
    return { approved: false, reason: "tty_failed" };
  }
  const expected = `APPROVE ${digest}`;
  if (line.trim() === expected) {
    return { approved: true, method: "tty" };
  }
  return { approved: false, reason: "tty_mismatch" };
}

/**
 * Production wiring: the McpServer instance for elicitation, plus the
 * shared `tty` namespace for the prompt fallback.
 *
 * The `mcpServer` passed in is whatever McpServer is handling the current
 * tool call (per-request in HTTP mode, lifelong in stdio mode). Each
 * registration captures the right one via closure.
 */
export function makeApprovalChannel(mcpServer: McpServer): ApprovalChannel {
  return {
    async tryElicit(preview, digest) {
      try {
        // McpServer's inner Server is where elicitInput lives in the SDK.
        const inner = (mcpServer as unknown as { server: { elicitInput?: (params: unknown) => Promise<{ action: string; content?: Record<string, unknown> }> } }).server;
        if (typeof inner?.elicitInput !== "function") return "unsupported";
        const result = await inner.elicitInput({
          message: `${preview}\n\nApprove broadcast?  digest: ${digest}`,
          requestedSchema: {
            type: "object",
            properties: {
              confirmed: {
                type: "boolean",
                description: "Set to true to broadcast this transaction.",
              },
            },
            required: ["confirmed"],
          },
        });
        const ok = result?.action === "accept" && result?.content?.confirmed === true;
        return { approved: ok };
      } catch {
        // Client doesn't support elicitation, request was cancelled mid-flight,
        // schema validation failed, transport hiccup, etc. Any of these
        // means we should fall through to TTY rather than broadcast.
        return "unsupported";
      }
    },
    isTtyAvailable: () => tty.isTtyAvailable(),
    promptTty: (prompt, timeoutMs) => tty.promptLine(prompt, { timeoutMs }),
  };
}
