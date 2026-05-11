/**
 * Phase 5 tests: audit log + rate limiting.
 *
 * Sections:
 *   A. TokenBucket unit semantics.
 *   B. Audit module: writes JSONL with chmod 600, redacts sensitive
 *      fields, never crashes on serialization issues.
 *   C. Signing rate limit fires BEFORE consumePending — a denied confirm
 *      does NOT burn its token.
 *   D. HTTP rate limit fires after Host/Origin but before bearer auth
 *      and JSON parsing.
 *   E. Audit content checks: send/confirm/unlock events present, NO raw
 *      tokens / passwords / mnemonics in the log.
 */

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { request as httpRequest } from "node:http";
import { mkdtempSync, rmSync, readFileSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP_HOME = mkdtempSync(join(tmpdir(), "kaspa-mcp-audit-"));
process.env.HOME = TMP_HOME;
delete process.env.KASPA_WALLET_PASSWORD;
delete process.env.KASPA_MNEMONIC;
delete process.env.KASPA_PRIVATE_KEY;
process.env.KASPA_ENABLE_SIGNING = "1";
process.env.KASPA_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
process.env.KASPA_NETWORK = "testnet-12";
// In-process rate limits high so unrelated sections don't starve each
// other; section C overrides per-test as needed.
process.env.KASPA_SIGNING_RATE_CAPACITY = "10000";
process.env.KASPA_SIGNING_RATE_REFILL_PER_SEC = "10000";

await import("./dist/services/setup.js");

const { TokenBucket } = await import("./dist/services/rate-limit.js");
const {
  audit,
  tokenHash,
  _resetForTests: auditReset,
  _flushRateLimitedForTests,
  _getAuditFilePath,
} = await import("./dist/services/audit.js");
const {
  sendTransactionHandler,
  confirmSendTransactionHandler,
  _drainSigningBucketForTests,
  _drainPreviewBucketForTests,
  _reconfigureSigningBucketForTests,
  _reconfigurePreviewBucketForTests,
} = await import("./dist/tools/wallet-tools.js");
const {
  createPending,
  _resetForTests: resetConfirms,
  _pendingSize,
} = await import("./dist/services/confirmations.js");

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

function bodyOf(r) { return r.content[0].text; }
function isErr(r) { return r.isError === true; }

function readAuditLines() {
  const path = _getAuditFilePath();
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l));
}

try {
  // ──────────────────────────────────────────────────────────────────
  // A. TokenBucket unit tests
  // ──────────────────────────────────────────────────────────────────
  {
    const b = new TokenBucket(3, 0); // capacity 3, no refill
    const taken = [b.consume(), b.consume(), b.consume(), b.consume()];
    check(
      "TokenBucket: capacity 3, no refill → 3 succeed then 1 fails",
      JSON.stringify(taken) === JSON.stringify([true, true, true, false]),
    );
  }
  {
    const b = new TokenBucket(2, 10); // capacity 2, 10/sec refill
    b.consume(); b.consume();
    // wait 150ms → expect ~1.5 tokens refilled
    await sleep(150);
    const next = b.consume(); // succeeds (we have ~1.5)
    const after = b.peek();
    check(
      "TokenBucket: refill restores tokens over time",
      next === true && after >= 0 && after < 1,
      `next=${next} after=${after.toFixed(3)}`,
    );
  }

  // ──────────────────────────────────────────────────────────────────
  // B. Audit module: write, chmod, JSON shape
  // ──────────────────────────────────────────────────────────────────
  {
    // Fresh write
    auditReset();
    try { rmSync(_getAuditFilePath(), { force: true }); } catch {}
    audit("wallet_unlocked", { source: "tty", address: "kaspatest:qzr...", network: "testnet-12" });
    audit("send_preview_created", { tokenHash: "deadbeef00000000", digest: "abcd1234" });
    const lines = readAuditLines();
    const mode = statSync(_getAuditFilePath()).mode & 0o777;
    const ok =
      lines.length === 2 &&
      lines[0].event === "wallet_unlocked" &&
      lines[1].event === "send_preview_created" &&
      typeof lines[0].ts === "string" &&
      typeof lines[0].pid === "number" &&
      mode === 0o600;
    check(
      "audit: JSONL write, mode 0o600, ts+pid+event present",
      ok,
      `lines=${lines.length} mode=${mode.toString(8)}`,
    );
  }

  // Audit non-crash on un-serializable input. BigInt is the cleanest
  // example: JSON.stringify throws TypeError. (Circular refs used to be
  // such an example, but the redactor's depth limit now handles them.)
  // audit() must swallow and not propagate either way.
  {
    auditReset();
    try { rmSync(_getAuditFilePath(), { force: true }); } catch {}
    let threw = false;
    try {
      // @ts-ignore — BigInt isn't JSON-serializable
      audit("rate_limited", { layer: "http", weird: 1n });
    } catch {
      threw = true;
    }
    const lines = readAuditLines();
    check(
      "audit: serialize failure swallowed, no propagation",
      !threw && lines.length === 0,
      `threw=${threw} lines=${lines.length}`,
    );
  }

  // ──────────────────────────────────────────────────────────────────
  // C. Signing rate limit fires BEFORE consumePending
  // ──────────────────────────────────────────────────────────────────
  {
    resetConfirms();
    auditReset();
    try { rmSync(_getAuditFilePath(), { force: true }); } catch {}
    const sampleParams = () => ({
      to: "kaspatest:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9ssxd5s7gn",
      amountSompi: "100000000",
      priorityFeeSompi: "0",
      network: "testnet-12",
      senderAddress: "kaspatest:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9ssxd5s7gn",
    });
    const { token } = createPending(sampleParams(), "1234", "preview");
    const beforeSize = _pendingSize();

    // Reconfigure to capacity=1+refill=0 then drain, so the bucket
    // genuinely stays empty for the duration of this assertion. (Plain
    // _drainForTests is ineffective when the default refill rate is high,
    // because microseconds of elapsed time replenishes the bucket.)
    _reconfigureSigningBucketForTests(1, 0);
    _drainSigningBucketForTests();

    const r = await confirmSendTransactionHandler(
      { confirm_token: token },
      {
        channel: { tryElicit: async () => ({ approved: true }), isTtyAvailable: () => false, promptTty: async () => "" },
        submit: async () => ({ txId: "should_not_be_called", fee: "0", totalTransactions: 1 }),
      },
    );
    const afterSize = _pendingSize();

    const rateLimited = isErr(r) && bodyOf(r).includes("rate limit");
    const tokenPreserved = afterSize === beforeSize; // entry NOT consumed
    // Force the bucketed audit flush so the event reaches disk.
    _flushRateLimitedForTests();
    const auditLines = readAuditLines();
    const hasRateLimitedEvent = auditLines.some(
      (l) => l.event === "rate_limited" && l.layer === "signing",
    );

    check(
      "signing rate limit: denial happens BEFORE consumePending (token preserved)",
      rateLimited && tokenPreserved,
      `rateLimited=${rateLimited} tokenPreserved=${tokenPreserved} (before=${beforeSize} after=${afterSize})`,
    );
    check(
      "signing rate limit: 'rate_limited' audit event written (bucketed)",
      hasRateLimitedEvent,
      `events=${auditLines.map((l) => l.event).join(",")}`,
    );
  }

  // ──────────────────────────────────────────────────────────────────
  // Preview rate limit (Phase 5 follow-up): sendTransactionHandler
  // consumes from the preview bucket BEFORE wallet/RPC work.
  // ──────────────────────────────────────────────────────────────────
  {
    auditReset();
    try { rmSync(_getAuditFilePath(), { force: true }); } catch {}
    _reconfigurePreviewBucketForTests(1, 0);
    _drainPreviewBucketForTests();
    const r = await sendTransactionHandler({
      to: "kaspatest:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9ssxd5s7gn",
      amount: "1.0",
    });
    _flushRateLimitedForTests();
    const auditLines = readAuditLines();
    const hasPreviewRL = auditLines.some(
      (l) => l.event === "rate_limited" && l.layer === "preview",
    );
    const ok = isErr(r) && bodyOf(r).includes("preview rate limit") && hasPreviewRL;
    check(
      "preview rate limit: send refused before wallet/RPC, bucketed audit recorded",
      ok,
      `body=${bodyOf(r).slice(0, 100)} previewRL=${hasPreviewRL}`,
    );
  }

  // ──────────────────────────────────────────────────────────────────
  // Pending-map cap: createPending throws after policy.maxPendingTx
  // ──────────────────────────────────────────────────────────────────
  {
    resetConfirms();
    const { PendingCapReachedError } = await import("./dist/services/confirmations.js");
    const { policy } = await import("./dist/services/policy.js");
    const cap = policy.maxPendingTx;
    const sample = () => ({
      to: "kaspatest:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9ssxd5s7gn",
      amountSompi: "100000000",
      priorityFeeSompi: "0",
      network: "testnet-12",
      senderAddress: "kaspatest:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9ssxd5s7gn",
    });
    for (let i = 0; i < cap; i++) {
      createPending(sample(), "1234", "p");
    }
    let threw = null;
    try {
      createPending(sample(), "1234", "p");
    } catch (e) {
      threw = e;
    }
    const ok =
      threw instanceof PendingCapReachedError &&
      threw.cap === cap &&
      _pendingSize() === cap;
    check(
      `pending-map cap: throws after ${cap} entries, size unchanged`,
      ok,
      `err=${threw?.name} cap=${threw?.cap} size=${_pendingSize()}`,
    );
  }

  // ──────────────────────────────────────────────────────────────────
  // Scrubber depth cap: very deep nesting collapses at MAX_SCRUB_DEPTH
  // into "[REDACTED_DEPTH]". This is the mechanism that makes circular
  // references survivable (the cycle keeps recursing until depth caps it).
  // ──────────────────────────────────────────────────────────────────
  {
    auditReset();
    try { rmSync(_getAuditFilePath(), { force: true }); } catch {}
    // Build an object nested deeper than MAX_SCRUB_DEPTH=6.
    let deep = { leaf: "kept" };
    for (let i = 0; i < 10; i++) deep = { next: deep };
    audit("send_preview_created", { d: deep });
    const lines = readAuditLines();
    const blob = JSON.stringify(lines[lines.length - 1] ?? {});
    const hasMarker = blob.includes("[REDACTED_DEPTH]");
    const noLeafLeak = !blob.includes('"leaf":"kept"');
    check(
      "audit: depth cap collapses deeply nested values with [REDACTED_DEPTH]",
      hasMarker && noLeafLeak,
      `hasMarker=${hasMarker} noLeafLeak=${noLeafLeak}`,
    );
  }

  // Circular references: the depth cap is what keeps an accidental cycle
  // from looping forever. The audit line should still get written (the
  // cycle is truncated mid-walk) and audit() must NOT throw.
  {
    auditReset();
    try { rmSync(_getAuditFilePath(), { force: true }); } catch {}
    const cyc = { name: "outer" };
    cyc.self = cyc;
    let threw = false;
    try {
      audit("send_preview_created", { cyc });
    } catch {
      threw = true;
    }
    const lines = readAuditLines();
    const ok =
      !threw &&
      lines.length === 1 &&
      JSON.stringify(lines[0]).includes("[REDACTED_DEPTH]");
    check(
      "audit: circular reference survives (depth cap, no throw, line written)",
      ok,
      `threw=${threw} lines=${lines.length}`,
    );
  }

  // ──────────────────────────────────────────────────────────────────
  // Central audit field-name redactor (pattern + nested).
  //
  // Covers the regressions the reviewer flagged: compound names like
  // confirm_token, walletPassword, privateKey, authHeader, plus nested
  // structures. *Hash suffixes are by-convention safe (correlation IDs).
  // ──────────────────────────────────────────────────────────────────
  {
    auditReset();
    try { rmSync(_getAuditFilePath(), { force: true }); } catch {}
    audit("send_preview_created", {
      // Safe correlation / public fields — must survive.
      tokenHash: "deadbeef00000000",
      previewHash: "feedcafe",
      digest: "abcd1234",
      address: "kaspatest:qzr...",
      // Exact-name matches.
      token: "should-be-redacted-1",
      password: "hunter2",
      mnemonic: "abandon abandon abandon",
      authorization: "Bearer xyz",
      seed: "shouldnt see this",
      // Compound names — the regression class the reviewer flagged.
      confirm_token: "compound-redact-1",
      confirmToken: "compound-redact-2",
      bearerToken: "compound-redact-3",
      walletPassword: "compound-redact-4",
      privateKey: "compound-redact-5",
      private_key: "compound-redact-6",
      authHeader: "compound-redact-7",
      mnemonicWords: "compound-redact-8",
      // Nested.
      wallet: {
        password: "nested-redact-1",
        address: "kaspatest:nested-keep",
        keys: { privateKey: "nested-redact-2", publicKey: "kept" },
      },
      // Array of objects.
      history: [
        { password: "array-redact-1", note: "kept" },
        { ok: true },
      ],
    });
    const lines = readAuditLines();
    const rec = lines[lines.length - 1];
    const blob = JSON.stringify(rec);

    const kept =
      rec?.tokenHash === "deadbeef00000000" &&
      rec?.previewHash === "feedcafe" &&
      rec?.digest === "abcd1234" &&
      rec?.address === "kaspatest:qzr..." &&
      rec?.wallet?.address === "kaspatest:nested-keep" &&
      rec?.wallet?.keys?.publicKey === "kept" &&
      rec?.history?.[0]?.note === "kept" &&
      rec?.history?.[1]?.ok === true;

    const redacted =
      rec?.token === "[REDACTED]" &&
      rec?.password === "[REDACTED]" &&
      rec?.mnemonic === "[REDACTED]" &&
      rec?.authorization === "[REDACTED]" &&
      rec?.seed === "[REDACTED]" &&
      rec?.confirm_token === "[REDACTED]" &&
      rec?.confirmToken === "[REDACTED]" &&
      rec?.bearerToken === "[REDACTED]" &&
      rec?.walletPassword === "[REDACTED]" &&
      rec?.privateKey === "[REDACTED]" &&
      rec?.private_key === "[REDACTED]" &&
      rec?.authHeader === "[REDACTED]" &&
      rec?.mnemonicWords === "[REDACTED]" &&
      rec?.wallet?.password === "[REDACTED]" &&
      rec?.wallet?.keys?.privateKey === "[REDACTED]" &&
      rec?.history?.[0]?.password === "[REDACTED]";

    // Cross-check: NO raw secret values anywhere in the serialized line.
    const noRawLeak =
      !blob.includes("hunter2") &&
      !blob.includes("Bearer xyz") &&
      !blob.includes("abandon abandon abandon") &&
      !blob.includes("should-be-redacted") &&
      !blob.includes("compound-redact") &&
      !blob.includes("nested-redact") &&
      !blob.includes("array-redact");

    check(
      "audit: central redactor scrubs compound + nested + array sensitive keys",
      kept && redacted && noRawLeak,
      kept && redacted && noRawLeak
        ? "ok"
        : `kept=${kept} redacted=${redacted} noRawLeak=${noRawLeak} blob=${blob.slice(0, 300)}`,
    );
  }
} finally {
  try { rmSync(TMP_HOME, { recursive: true, force: true }); } catch { /* */ }
}

// ──────────────────────────────────────────────────────────────────────
// D + E. HTTP rate limit ordering + audit content over real wire
// ──────────────────────────────────────────────────────────────────────
async function runHttpSection() {
  const PORT = 4200;
  const TOKEN = "a".repeat(40);
  const RECIPIENT =
    "kaspatest:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9ssxd5s7gn";

  // Use a temp HOME so the spawned server writes audit.log to a path
  // this test can read.
  const httpHome = mkdtempSync(join(tmpdir(), "kaspa-mcp-audit-http-"));

  const env = {
    ...process.env,
    HOME: httpHome,
    KASPA_ENABLE_HTTP: "1",
    KASPA_MCP_TOKEN: TOKEN,
    KASPA_ENDPOINT: "ws://127.0.0.1:1",
    PORT: String(PORT),
    KASPA_ENABLE_SIGNING: "1",
    KASPA_TEST_MOCK_TXSERVICE: "1",
    KASPA_MNEMONIC:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    KASPA_NETWORK: "testnet-12",
    // Tight HTTP rate limit to exercise the 429 path quickly.
    KASPA_HTTP_RATE_CAPACITY: "3",
    KASPA_HTTP_RATE_REFILL_PER_SEC: "0",
    KASPA_SIGNING_RATE_CAPACITY: "10000",
    KASPA_SIGNING_RATE_REFILL_PER_SEC: "10000",
  };
  delete env.KASPA_WALLET_PASSWORD;
  delete env.KASPA_PRIVATE_KEY;

  const server = spawn("node", ["dist/index.js"], { env, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  server.stderr.on("data", (b) => (stderr += b.toString()));

  function rawRequest({ method = "GET", path = "/", headers = {}, body }) {
    return new Promise((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port: PORT, path, method, headers }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
      });
      req.on("error", reject);
      if (body) req.write(body);
      req.end();
    });
  }

  // Wait for bind
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    try {
      const r = await rawRequest({ path: "/health", headers: { authorization: `Bearer ${TOKEN}` } });
      if (r.status === 200 || r.status === 503) break;
    } catch {}
    await sleep(120);
  }

  try {
    // ── D1: rate limit eventually fires under capacity 3 + 0 refill.
    //    The wait-for-listener loop above already consumed some bucket
    //    tokens, so we don't assert an exact prefix length — instead we
    //    require that within capacity+probe count requests, the bucket
    //    transitions from healthy to rate-limited, and once limited it
    //    STAYS limited (refill=0).
    const sequence = [];
    for (let i = 0; i < 10; i++) {
      const r = await rawRequest({ path: "/health", headers: { authorization: `Bearer ${TOKEN}` } });
      sequence.push(r.status);
    }
    const firstRateLimited = sequence.findIndex((s) => s === 429);
    const allLimitedAfter = firstRateLimited >= 0 &&
      sequence.slice(firstRateLimited).every((s) => s === 429);
    const okSequence =
      firstRateLimited >= 0 && // at least one 429
      firstRateLimited <= 3 && // happens within ~capacity of test starting
      allLimitedAfter;         // and stays limited (no refill)
    check(
      "HTTP rate limit: bucket exhausts and stays exhausted (capacity 3, refill 0)",
      okSequence,
      `statuses=${sequence.join(",")} firstLimited@${firstRateLimited}`,
    );

    // ── D-bound: a flood of denied requests does NOT produce a flood of
    //    audit lines. The bucketed flush writes a single line per layer
    //    per ~5s window; we issue 50 denials and verify the file did not
    //    grow proportionally.
    const auditPath = join(httpHome, ".kaspa-mcp", "audit.log");
    const linesBefore = existsSync(auditPath)
      ? readFileSync(auditPath, "utf8").split("\n").filter((l) => l).length
      : 0;
    for (let i = 0; i < 50; i++) {
      await rawRequest({ path: "/health", headers: { authorization: `Bearer ${TOKEN}` } });
    }
    const linesAfter = existsSync(auditPath)
      ? readFileSync(auditPath, "utf8").split("\n").filter((l) => l).length
      : 0;
    // 50 denied requests at 0 refill ⇒ all 50 hit auditRateLimited; with
    // 5s flush window and ~no time elapsed, expect at most 1-2 new lines.
    const grew = linesAfter - linesBefore;
    check(
      "audit: 50 rate-limit denials produce ≤ 3 audit lines (bucketed, not per-event)",
      grew <= 3,
      `linesBefore=${linesBefore} linesAfter=${linesAfter} grew=${grew}`,
    );

    // ── D2: rate-limit happens BEFORE bearer auth (no-token request that
    //    would normally 401 still hits 429 once bucket is dry).
    // Wait a moment — let any timing edge clear, then verify the bucket is
    // empty.
    const r401or429 = await rawRequest({ path: "/health" /* no auth */ });
    // With bucket dry, request without bearer must still be denied by
    // EITHER 429 (rate limit, which runs before bearer) OR 401 (if for
    // some reason a token leaked in). 429 is the correct path.
    check(
      "HTTP rate limit: bucket-dry + no bearer → 429 (rate runs before bearer)",
      r401or429.status === 429,
      `status=${r401or429.status}`,
    );

    // ── D3: rate-limit does NOT fire before Host/Origin checks.
    //    A wrong-Host request returns 403, NOT 429, even though bucket dry.
    const rHost = await rawRequest({
      path: "/health",
      headers: { authorization: `Bearer ${TOKEN}`, host: "evil.example:80" },
    });
    check(
      "HTTP rate limit: wrong Host → 403 (Host check fires before rate limit)",
      rHost.status === 403,
      `status=${rHost.status}`,
    );
  } finally {
    // Send SIGTERM then WAIT for the child to actually exit. Just sleeping
    // doesn't give the shutdown handler (flushPendingAudit → audit append
    // → exit) enough deterministic time, especially on cold-start macOS.
    const exited = new Promise((resolve) => server.on("exit", resolve));
    server.kill("SIGTERM");
    await Promise.race([exited, sleep(3000)]);
  }

  // ── E. Audit content over the wire ────────────────────────────────
  const auditPath = join(httpHome, ".kaspa-mcp", "audit.log");
  if (existsSync(auditPath)) {
    const lines = readFileSync(auditPath, "utf8")
      .split("\n")
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l));
    const blob = lines.map((l) => JSON.stringify(l)).join("\n");

    // Should contain a wallet_unlocked event? Actually no — KASPA_MNEMONIC
    // was set, so unlock was skipped. Should contain rate_limited events.
    const hasRateLimited = lines.some((l) => l.event === "rate_limited");

    // Sensitive content checks: bearer token and mnemonic words MUST NOT
    // appear anywhere in the audit log.
    const bearerLeak = blob.includes("a".repeat(40));
    const mnemonicLeak = /\babandon\s+abandon\s+abandon\b/.test(blob);
    // KASPA_MCP_TOKEN itself
    const tokenStringLeak = blob.includes("aaaaaaaaaaaaaaaaaaaa");

    check(
      "audit: rate_limited events recorded from HTTP layer",
      hasRateLimited,
      `events=${lines.map((l) => l.event).join(",")}`,
    );
    check(
      "audit: no bearer token in log",
      !bearerLeak && !tokenStringLeak,
      `bearerLeak=${bearerLeak} tokenStringLeak=${tokenStringLeak}`,
    );
    check(
      "audit: no mnemonic in log",
      !mnemonicLeak,
    );
  } else {
    check("audit: file present after HTTP run", false, `path=${auditPath} missing`);
  }

  // Print stderr for debugging if audit file is missing.
  if (!existsSync(join(httpHome, ".kaspa-mcp", "audit.log"))) {
    console.error("--- child stderr (debug) ---");
    console.error(stderr.slice(0, 2000));
    console.error("--- end ---");
  }
  try { rmSync(httpHome, { recursive: true, force: true }); } catch { /* */ }
  return stderr;
}

await runHttpSection();

const failed = results.filter((r) => !r.ok);
if (failed.length) {
  console.error(`\n${failed.length}/${results.length} checks failed`);
  process.exit(1);
}
console.log(`\nall ${results.length} checks passed`);
