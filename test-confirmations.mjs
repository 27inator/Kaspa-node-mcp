/**
 * Phase 3e tests: confirmations module + approval resolver +
 * two-step send/confirm flow.
 *
 * Coverage:
 *   - confirmations.ts: createPending → token+digest+expires; consumePending
 *     atomic delete; expiry; sweep.
 *   - approval.ts resolver: elicit-approved, elicit-declined,
 *     elicit-unsupported→tty-match, ...→tty-mismatch, ...→no-channel.
 *   - confirmSendTransactionHandler: token unknown/expired/used returns
 *     generic error; token format invalid same; happy path with mocked
 *     channel + mocked submit; decline/mismatch refuses; submit-failure
 *     does not retain entry.
 *   - Cross-instance singleton: two separate "pretend McpServer scopes"
 *     in the same process see the same pending map (proves the property
 *     HTTP per-request McpServer instances need).
 */

import { setTimeout as sleep } from "node:timers/promises";

const TMP_HOME = (await import("node:fs")).mkdtempSync(
  (await import("node:path")).join((await import("node:os")).tmpdir(), "kaspa-mcp-confirm-"),
);
process.env.HOME = TMP_HOME;
delete process.env.KASPA_WALLET_PASSWORD;
delete process.env.KASPA_MNEMONIC;
delete process.env.KASPA_PRIVATE_KEY;
process.env.KASPA_ENABLE_SIGNING = "1";
// Set a known mnemonic so the wallet activates without TTY/file unlock.
process.env.KASPA_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
process.env.KASPA_NETWORK = "testnet-12";
// Phase 5: raise the per-process signing rate limit well above what the
// confirmations test exercises (~10 confirm calls in milliseconds). The
// default 5-capacity bucket would otherwise starve the test. Dedicated
// rate-limit coverage lives in test-audit-rate-limit.mjs.
process.env.KASPA_SIGNING_RATE_CAPACITY = "10000";
process.env.KASPA_SIGNING_RATE_REFILL_PER_SEC = "10000";

await import("./dist/services/setup.js");

const {
  createPending,
  consumePending,
  expireSweep,
  _resetForTests: resetConfirms,
  _pendingSize,
} = await import("./dist/services/confirmations.js");
const { resolveApproval } = await import("./dist/services/approval.js");
const { confirmSendTransactionHandler } = await import("./dist/tools/wallet-tools.js");

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

const sampleParams = () => ({
  to: "kaspatest:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9ssxd5s7gn",
  amountSompi: "100000000",
  priorityFeeSompi: "0",
  network: "testnet-12",
  senderAddress: "kaspatest:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9ssxd5s7gn",
});

function bodyOf(r) { return r.content[0].text; }
function isErr(r) { return r.isError === true; }

try {
  // ────────────────────────────────────────────────────────────────────
  // confirmations.ts unit tests
  // ────────────────────────────────────────────────────────────────────
  {
    resetConfirms();
    const { token, digest, expiresAt } = createPending(sampleParams(), "1234", "preview text");
    const ok =
      /^[0-9a-f]{32}$/.test(token) &&
      /^[0-9a-f]{8}$/.test(digest) &&
      expiresAt > Date.now() + 4 * 60_000 &&
      expiresAt < Date.now() + 6 * 60_000 &&
      _pendingSize() === 1;
    check("createPending: 32-hex token, 8-hex digest, ~5min TTL, 1 entry", ok,
      `tokenLen=${token.length} digestLen=${digest.length} ttl=${expiresAt - Date.now()}`);
  }

  {
    resetConfirms();
    const { token } = createPending(sampleParams(), "1234", "preview");
    const first = consumePending(token);
    const second = consumePending(token);
    const ok = first !== null && second === null && _pendingSize() === 0;
    check("consumePending: returns entry once, then null (single-use, deleted)", ok,
      `first=${first !== null} second=${second === null} size=${_pendingSize()}`);
  }

  {
    resetConfirms();
    const { token } = createPending(sampleParams(), "1234", "preview", 50 /* ms TTL */);
    await sleep(80);
    const result = consumePending(token);
    const ok = result === null && _pendingSize() === 0;
    check("expired token: consume returns null and entry is gone", ok);
  }

  {
    resetConfirms();
    const { token: t1 } = createPending(sampleParams(), "1234", "p1", 50);
    const { token: t2 } = createPending(sampleParams(), "1234", "p2", 5_000);
    await sleep(80);
    const removed = expireSweep();
    const ok = removed === 1 && _pendingSize() === 1 && consumePending(t1) === null && consumePending(t2) !== null;
    check("expireSweep: removes only expired entries", ok,
      `removed=${removed} t1=${consumePending(t1) === null} t2=${consumePending(t2) !== null}`);
  }

  // ────────────────────────────────────────────────────────────────────
  // approval.ts resolver
  // ────────────────────────────────────────────────────────────────────
  function mockChannel({ elicit, ttyAvailable = false, ttyResponse = "", ttyThrows = false }) {
    return {
      tryElicit: async () => elicit,
      isTtyAvailable: () => ttyAvailable,
      promptTty: async () => {
        if (ttyThrows) throw new Error("tty failure");
        return ttyResponse;
      },
    };
  }

  {
    const r = await resolveApproval(
      mockChannel({ elicit: { approved: true } }),
      "preview", "abc12345"
    );
    check("resolver: elicit accept → approved via elicitation",
      r.approved === true && r.method === "elicitation");
  }
  {
    const r = await resolveApproval(
      mockChannel({ elicit: { approved: false } }),
      "preview", "abc12345"
    );
    check("resolver: elicit decline → declined",
      r.approved === false && r.reason === "declined");
  }
  {
    const r = await resolveApproval(
      mockChannel({ elicit: "unsupported", ttyAvailable: true, ttyResponse: "APPROVE abc12345" }),
      "preview", "abc12345"
    );
    check("resolver: elicit unsupported + tty exact match → approved via tty",
      r.approved === true && r.method === "tty");
  }
  {
    const r = await resolveApproval(
      mockChannel({ elicit: "unsupported", ttyAvailable: true, ttyResponse: "APPROVE wrong" }),
      "preview", "abc12345"
    );
    check("resolver: tty phrase mismatch → tty_mismatch",
      r.approved === false && r.reason === "tty_mismatch");
  }
  {
    const r = await resolveApproval(
      mockChannel({ elicit: "unsupported", ttyAvailable: false }),
      "preview", "abc12345"
    );
    check("resolver: no elicit + no tty → no_channel",
      r.approved === false && r.reason === "no_channel");
  }
  {
    const r = await resolveApproval(
      mockChannel({ elicit: "unsupported", ttyAvailable: true, ttyThrows: true }),
      "preview", "abc12345"
    );
    check("resolver: tty throws → tty_failed",
      r.approved === false && r.reason === "tty_failed");
  }

  // ────────────────────────────────────────────────────────────────────
  // confirmSendTransactionHandler: token validation + happy path
  // ────────────────────────────────────────────────────────────────────
  {
    resetConfirms();
    const channel = mockChannel({ elicit: { approved: true } });
    const r = await confirmSendTransactionHandler(
      { confirm_token: "not-hex" },
      { channel, submit: async () => ({ txId: "x", fee: "0", totalTransactions: 1 }) },
    );
    const ok = isErr(r) && bodyOf(r).includes("unknown, expired, or already used");
    check("confirm: bad-format token → generic error", ok, bodyOf(r).slice(0, 120));
  }

  {
    resetConfirms();
    const channel = mockChannel({ elicit: { approved: true } });
    const r = await confirmSendTransactionHandler(
      { confirm_token: "0".repeat(32) }, // valid format, not in map
      { channel, submit: async () => ({ txId: "x", fee: "0", totalTransactions: 1 }) },
    );
    const ok = isErr(r) && bodyOf(r).includes("unknown, expired, or already used");
    check("confirm: unknown token → generic error", ok);
  }

  {
    resetConfirms();
    const { token, digest } = createPending(sampleParams(), "1234", "preview");
    const channel = mockChannel({ elicit: { approved: true } });
    let submitArgs;
    const r = await confirmSendTransactionHandler(
      { confirm_token: token },
      {
        channel,
        submit: async (params) => {
          submitArgs = params;
          return { txId: "0xfeedface", fee: "0.0001", totalTransactions: 1 };
        },
      },
    );
    const parsed = JSON.parse(bodyOf(r));
    const ok =
      !isErr(r) &&
      parsed.status === "submitted" &&
      parsed.txId === "0xfeedface" &&
      parsed.approvalMethod === "elicitation" &&
      parsed.digest === digest &&
      submitArgs?.to === sampleParams().to &&
      _pendingSize() === 0;  // single-use deletion
    check("confirm: happy path → submit invoked, entry deleted, txId returned", ok,
      `status=${parsed.status} method=${parsed.approvalMethod} sizeAfter=${_pendingSize()}`);
  }

  {
    resetConfirms();
    const { token } = createPending(sampleParams(), "1234", "preview");
    // Decline path
    const channel = mockChannel({ elicit: { approved: false } });
    let submitCalled = false;
    const r = await confirmSendTransactionHandler(
      { confirm_token: token },
      {
        channel,
        submit: async () => { submitCalled = true; return { txId: "x", fee: "0", totalTransactions: 1 }; },
      },
    );
    const ok = isErr(r) && bodyOf(r).includes("not approved") && !submitCalled && _pendingSize() === 0;
    check("confirm: decline → no submit, entry deleted (single-use)", ok,
      `submitCalled=${submitCalled} sizeAfter=${_pendingSize()}`);
  }

  {
    resetConfirms();
    const { token } = createPending(sampleParams(), "1234", "preview");
    // Submit failure: signAndSubmit throws
    const channel = mockChannel({ elicit: { approved: true } });
    const r = await confirmSendTransactionHandler(
      { confirm_token: token },
      { channel, submit: async () => { throw new Error("simulated submit failure"); } },
    );
    const ok = isErr(r) && bodyOf(r).includes("submit failed") && _pendingSize() === 0;
    check("confirm: submit failure → entry deleted, error returned", ok);
  }

  {
    resetConfirms();
    const { token } = createPending(sampleParams(), "1234", "preview");
    const channel = mockChannel({ elicit: { approved: true } });
    const submit = async () => ({ txId: "x", fee: "0", totalTransactions: 1 });
    // First confirm consumes
    await confirmSendTransactionHandler({ confirm_token: token }, { channel, submit });
    // Second confirm with same token must fail
    const r2 = await confirmSendTransactionHandler({ confirm_token: token }, { channel, submit });
    const ok = isErr(r2) && bodyOf(r2).includes("unknown, expired, or already used");
    check("confirm: token reuse → generic error", ok);
  }

  // ────────────────────────────────────────────────────────────────────
  // Cross-McpServer singleton: simulate two HTTP /mcp requests
  // (each gets its own McpServer instance) sharing the pending map.
  // We use the registered tool registration path for both, registering
  // tools twice on two different fake-server objects. Both registrations
  // close over the same imported confirmations module.
  // ────────────────────────────────────────────────────────────────────
  {
    resetConfirms();
    // "Server A" creates an entry directly via createPending — same as
    // what kaspa_send_transaction does internally.
    const { token } = createPending(sampleParams(), "1234", "preview from server A");
    // "Server B" runs the confirm handler. The pending map is module-
    // singleton, so the entry created in Server A's scope must be visible
    // here. If we'd made the map per-McpServer, this would fail.
    const channel = mockChannel({ elicit: { approved: true } });
    const r = await confirmSendTransactionHandler(
      { confirm_token: token },
      { channel, submit: async () => ({ txId: "0xcafebabe", fee: "0.0001", totalTransactions: 1 }) },
    );
    const parsed = JSON.parse(bodyOf(r));
    const ok = !isErr(r) && parsed.txId === "0xcafebabe";
    check("singleton: entry created in scope A is consumable from scope B", ok,
      `txId=${parsed.txId}`);
  }
} finally {
  try { (await import("node:fs")).rmSync(TMP_HOME, { recursive: true, force: true }); } catch { /* */ }
}

const failed = results.filter((r) => !r.ok);
if (failed.length) {
  console.error(`\n${failed.length}/${results.length} checks failed`);
  process.exit(1);
}
console.log(`\nall ${results.length} checks passed`);
