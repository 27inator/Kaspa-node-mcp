/**
 * Phase 1 integration smoke test: HTTP middleware ordering and behavior.
 *
 * Spawns the built server with HTTP enabled + a known token + a clearly
 * unreachable KASPA_ENDPOINT (so the node-connect fails in the background
 * and /health reports "disconnected" but auth checks still run).
 *
 * Asserts:
 *   1. Missing Authorization → 401
 *   2. Wrong bearer            → 401
 *   3. Wrong Host header       → 403
 *   4. Disallowed Origin       → 403
 *   5. Empty allowlist + no Origin + valid bearer → /health → 503 disconnected
 *   6. Body cap on /mcp        → 413
 *   7. POST /mcp without bearer → 401 (auth runs before json parser)
 */

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { request as httpRequest } from "node:http";

/**
 * Low-level HTTP request that honors arbitrary Host headers (fetch() rewrites
 * Host to match the URL, so we can't use it to test DNS-rebinding defense).
 */
function rawRequest({ path = "/", method = "GET", headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port: PORT, path, method, headers },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            body: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

const PORT = 4137;
const TOKEN = "x".repeat(40); // valid: ascii, >=32 chars
const BASE = `http://127.0.0.1:${PORT}`;

const env = {
  ...process.env,
  KASPA_ENABLE_HTTP: "1",
  KASPA_MCP_TOKEN: TOKEN,
  KASPA_ENDPOINT: "ws://127.0.0.1:1", // guaranteed-fail port
  PORT: String(PORT),
};

const server = spawn("node", ["dist/index.js"], { env, stdio: ["ignore", "ignore", "pipe"] });
let stderr = "";
server.stderr.on("data", (b) => { stderr += b.toString(); });

async function waitForListener(timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/health`, { headers: { host: `127.0.0.1:${PORT}` } });
      if (r.status === 401 || r.status === 403 || r.status === 503 || r.status === 200) return;
    } catch {}
    await sleep(100);
  }
  throw new Error(`server did not start within ${timeoutMs}ms\nstderr:\n${stderr}`);
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

try {
  await waitForListener();

  // 1. Missing Authorization
  {
    const r = await fetch(`${BASE}/health`);
    check("missing Authorization → 401", r.status === 401, `got ${r.status}`);
  }

  // 2. Wrong bearer
  {
    const r = await fetch(`${BASE}/health`, {
      headers: { authorization: "Bearer wrong-token-here-also-32+chars-long-yes" },
    });
    check("wrong bearer → 401", r.status === 401, `got ${r.status}`);
  }

  // 3. Wrong Host header (fetch() can't override Host, so use http.request)
  {
    const r = await rawRequest({
      path: "/health",
      headers: {
        host: "evil.example:80",
        authorization: `Bearer ${TOKEN}`,
      },
    });
    check("wrong Host → 403", r.status === 403, `got ${r.status} body=${r.body}`);
  }

  // 4. Disallowed Origin (allowlist is empty by default, so any Origin is rejected)
  {
    const r = await fetch(`${BASE}/health`, {
      headers: { authorization: `Bearer ${TOKEN}`, origin: "http://attacker.example" },
    });
    check("disallowed Origin → 403", r.status === 403, `got ${r.status}`);
  }

  // 5. Happy path: valid bearer, no Origin, correct Host. Upstream is dead so
  //    isConnected() returns false → /health returns 503 with {status:"disconnected"}.
  {
    const r = await fetch(`${BASE}/health`, {
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    const body = await r.json();
    const ok =
      r.status === 503 &&
      body.status === "disconnected" &&
      !("endpoint" in body); // /health must not leak the upstream URL
    check(
      "valid bearer + dead upstream → 503 disconnected (no endpoint leak)",
      ok,
      `status=${r.status} body=${JSON.stringify(body)}`
    );
  }

  // 6. Body cap on /mcp (300kb > 256kb limit)
  {
    const big = "x".repeat(300_000);
    const r = await fetch(`${BASE}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ blob: big }),
    });
    // express.json with a limit returns 413 on oversize.
    check("/mcp oversized body → 413", r.status === 413, `got ${r.status}`);
  }

  // 7. POST /mcp without bearer → 401 (auth runs before json parser)
  {
    const r = await fetch(`${BASE}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
    });
    check("/mcp without bearer → 401 (auth before json)", r.status === 401, `got ${r.status}`);
  }

  // 8. Authenticated MCP initialize round-trip. Proves the per-request
  //    server/transport lifecycle works end-to-end.
  {
    const r = await fetch(`${BASE}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${TOKEN}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "phase1-smoke", version: "0.0.1" },
        },
      }),
    });
    const body = await r.text();
    let parsed;
    try { parsed = JSON.parse(body); } catch { parsed = null; }
    const ok =
      r.status === 200 &&
      parsed?.jsonrpc === "2.0" &&
      parsed?.id === 1 &&
      parsed?.result?.serverInfo?.name === "kaspa-node-mcp-server";
    check(
      "authenticated initialize → serverInfo round-trip",
      ok,
      `status=${r.status} body=${body.slice(0, 200)}`
    );
  }

  // 9. Concurrent initialize requests (proves no singleton-server race).
  //    With a shared McpServer, the second connect() would error out.
  {
    const mkInit = (id) =>
      fetch(`${BASE}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${TOKEN}`,
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id,
          method: "initialize",
          params: {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: `concurrent-${id}`, version: "0.0.1" },
          },
        }),
      }).then(async (r) => ({ status: r.status, body: await r.text() }));

    const [a, b, c] = await Promise.all([mkInit(11), mkInit(12), mkInit(13)]);
    const allOk = [a, b, c].every(
      (r) => r.status === 200 && r.body.includes("kaspa-node-mcp-server")
    );
    check(
      "3x concurrent initialize → all succeed (no singleton race)",
      allOk,
      `statuses=${[a, b, c].map((r) => r.status).join(",")}`
    );
  }
} finally {
  server.kill("SIGTERM");
  await sleep(200);
}

const failed = results.filter((r) => !r.ok);
if (failed.length) {
  console.error(`\n${failed.length}/${results.length} checks failed`);
  console.error("server stderr:\n" + stderr);
  process.exit(1);
}
console.log(`\nall ${results.length} checks passed`);
