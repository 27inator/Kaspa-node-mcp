# kaspa-node-mcp

MCP server for interacting with any [rusty-kaspa](https://github.com/kaspanet/rusty-kaspa) node via wRPC Borsh over WebSocket.

Gives AI agents (Claude Code, OpenClaw, etc.) the ability to query the Kaspa blockchain, manage a wallet, preview transactions, and — only with explicit human approval — broadcast them.

## What's in the box

- **Read-only queries** against any Kaspa network (mainnet, testnet-10/-11/-12)
- **BIP39/BIP44 wallet** with AES-256-GCM + scrypt encrypted persistence
- **Hardened HTTP transport** (off by default; loopback-only, bearer-auth, Host/Origin allowlist)
- **Two-step signing** — the model proposes, the *user* approves via MCP elicitation or a `/dev/tty` prompt
- **Operator-set caps** on per-tx spend, preview rate, and signing rate
- **Append-only audit log** at `~/.kaspa-mcp/audit.log`
- **KPM anchor verification** (`KPM1 || mode || hash` payload format)

> **Status: hardening pass complete (Phases 0–5).** The README, the threat model, and the launch recipes below all reflect the current code. There are no `kaspa_load_wallet`, no `TRANSPORT=http`, no password-as-tool-argument paths anymore — if you see those mentioned somewhere, that doc is stale.

## Security model

The default posture is **read-only stdio**. Every additional capability is gated behind an explicit env flag so a misconfigured launch never accidentally exposes signing or HTTP.

| Capability | Default | Enable with |
|---|---|---|
| Read-only Kaspa queries | ✓ | (always on) |
| HTTP transport | OFF | `KASPA_ENABLE_HTTP=1` + `KASPA_MCP_TOKEN` |
| Wallet setup (generate mnemonic / save) | OFF | `KASPA_ENABLE_WALLET_SETUP=1` |
| Signing (preview + confirm send) | OFF | `KASPA_ENABLE_SIGNING=1` |

Tools whose gate is OFF are **not advertised** in `tools/list` — the model can't see them, can't try them.

### Threat model — what this server defends against

| Threat | Defense |
|---|---|
| Browser pages reaching loopback HTTP via DNS rebinding | `Host` header allowlist, bind to `127.0.0.1` only |
| Cross-origin probes | `Origin` allowlist (empty by default — any `Origin` is rejected) |
| Bearer token brute force | Constant-time compare, ASCII-only token, ≥32 chars, **process-global rate limit** sits before auth |
| Body-size DoS | 256 KB body cap, applied *after* auth so unauth requests don't force JSON parsing |
| Per-request McpServer race | One fresh `McpServer` per `/mcp` request, with shared upstream client |
| Model self-authorizing a broadcast | `kaspa_send_transaction` builds a preview only; `kaspa_confirm_send_transaction` requires user approval via MCP elicitation or `/dev/tty` — the model cannot synthesize either response |
| Stale preview replayed after parameters changed | Confirm digest includes a server nonce; single-use, 5-min TTL pending map |
| Confirm-token reuse / leakage | Atomic consume-then-delete; tokens never logged raw (sha256[:16] hashes in audit) |
| Excessive amount via tool args | Per-tx cap on **amount + priority fee** (`KASPA_MAX_SOMPI_PER_TX`, default 1000 KAS) |
| Preview spam filling the pending map / burning RPC | Preview rate limit + pending-map cap (`KASPA_MAX_PENDING_TX`, default 50) |
| Mnemonic / password in LLM transcript | Mnemonic displayed **only on `/dev/tty`**; password from env or `/dev/tty`, never as a tool argument |
| Audit-log disk flood from a denial loop | Rate-limit events are accumulated in memory and flushed once per 5s window |

### What this server does NOT defend against

- A compromised local host. If an attacker has read access to `~/.kaspa-mcp/wallet.enc` AND can grab the password (env, keylogger, swap), they have the wallet. The encryption is meaningful against casual disk reads, not local-root.
- A malicious Kaspa node. The server trusts the upstream node it's pointed at.
- Side-channel leaks of the mnemonic through `kaspa-wasm` internals. JS strings are immutable; we drop our references but cannot guarantee in-process erasure.

## Tools

### Always registered (read-only)

| Tool | Purpose |
|---|---|
| `kaspa_get_info` | Node health |
| `kaspa_get_server_info` | Network ID, RPC version, DAA score |
| `kaspa_get_block_dag_info` | DAG state |
| `kaspa_get_block` | Fetch block by hash |
| `kaspa_get_balance` | Address balance |
| `kaspa_get_utxos` | UTXO set for up to 100 addresses |
| `kaspa_find_transaction_in_block` | Find/parse a tx in a specific block |
| `kaspa_search_blocks_for_transaction` | BFS recent blocks for a tx |
| `kaspa_verify_kpm_anchor` | Verify a KPM anchor payload |
| `kaspa_get_coin_supply` | Circulating / max supply |
| `kaspa_get_my_address` | Show active wallet address (errors if none) |
| `kaspa_estimate_fee` | Fee estimates |

### Gated by `KASPA_ENABLE_WALLET_SETUP=1`

| Tool | Purpose |
|---|---|
| `kaspa_generate_mnemonic` | Generate BIP39 mnemonic, encrypt to disk. Mnemonic is displayed **only on `/dev/tty`**; the tool result returns `{status, path, address, fingerprint}` — never the words. |
| `kaspa_save_wallet` | Encrypt currently-active mnemonic-based wallet to disk. Password from env or `/dev/tty`. Schema is `{}` — no `password` argument. |

### Gated by `KASPA_ENABLE_SIGNING=1`

| Tool | Purpose |
|---|---|
| `kaspa_send_transaction` | **Preview only.** Builds and validates a transaction, stores it in a pending-confirmation map, returns `{confirm_token, digest, preview, expires_at}`. Does NOT sign, does NOT broadcast. |
| `kaspa_confirm_send_transaction` | Asks the user to approve via MCP elicitation (preferred) or `/dev/tty` prompt (fallback). Only on approval: re-fetches UTXOs, signs, broadcasts. Single-use token; 5-min TTL. |

## Wallet activation — how it gets a wallet

Three ways, in order of preference:

1. **Encrypted file** at `~/.kaspa-mcp/wallet.enc`, unlocked at startup. Requires `KASPA_ENABLE_SIGNING=1` *or* `KASPA_ENABLE_WALLET_SETUP=1`. Password source: `KASPA_WALLET_PASSWORD` env (tried first if set) → `/dev/tty` prompt (60s timeout). Unlock runs **after** the MCP transport is up, in a child `sh` process, so it doesn't block initialization.
2. `KASPA_MNEMONIC` env var.
3. `KASPA_PRIVATE_KEY` env var (raw hex; cannot be re-saved with `kaspa_save_wallet`).

The old `kaspa_load_wallet(password)` tool is **removed**. Tool arguments traverse the LLM's context window; passing a password through one defeats the encryption.

## Launch recipes

### Read-only (default — no wallet, no signing)

```bash
KASPA_ENDPOINT=ws://127.0.0.1:17210 node dist/index.js
```

Use this for chain queries, KPM anchor verification, etc. None of the wallet/signing tools are advertised.

### Claude Code MCP config (stdio)

```json
{
  "mcpServers": {
    "kaspa-node": {
      "command": "node",
      "args": ["/path/to/kaspa-node-mcp/dist/index.js"],
      "env": {
        "KASPA_ENDPOINT": "ws://127.0.0.1:17210"
      }
    }
  }
}
```

For signing, add `KASPA_ENABLE_SIGNING: "1"` to the `env` block (and have an encrypted wallet or `KASPA_MNEMONIC` in env).

### Wallet setup (one-time, interactive)

```bash
KASPA_ENABLE_WALLET_SETUP=1 KASPA_ENDPOINT=ws://127.0.0.1:17210 node dist/index.js
```

Then ask Claude (or whatever client) to call `kaspa_generate_mnemonic`. The 24 words appear on your terminal — **write them down** — and the encrypted file is created. Stop the server, drop the setup flag, and relaunch with signing enabled.

### Production signing (stdio, interactive)

```bash
KASPA_ENABLE_SIGNING=1 \
KASPA_ENDPOINT=ws://127.0.0.1:17210 \
node dist/index.js
```

At startup the server prompts for the wallet password on `/dev/tty`. Once unlocked, `kaspa_send_transaction` builds previews; `kaspa_confirm_send_transaction` asks the user (via elicitation or TTY) before broadcasting.

For headless setups, set `KASPA_WALLET_PASSWORD=...` to skip the prompt. Note that env vars can leak via shell history, launch configs, crash reports, and process inspection — prefer the TTY path for interactive launches.

### HTTP transport (hardened)

```bash
KASPA_ENABLE_HTTP=1 \
KASPA_MCP_TOKEN="$(openssl rand -hex 32)" \
KASPA_ENDPOINT=ws://127.0.0.1:17210 \
PORT=3001 \
node dist/index.js
```

Then register `http://127.0.0.1:3001/mcp` with the bearer token in your client. The server binds **127.0.0.1 only**; cross-host access requires a separate reverse proxy you control.

The legacy `TRANSPORT=http` flag is gone — the server exits 1 if it sees it without `KASPA_ENABLE_HTTP=1`, to make sure stale launch configs surface the migration.

## Environment variable reference

### Network / wallet

| Variable | Default | Purpose |
|---|---|---|
| `KASPA_ENDPOINT` | `ws://127.0.0.1:17210` | wRPC Borsh WebSocket URL |
| `KASPA_NETWORK` | *(auto)* | `mainnet` / `testnet-10` / `testnet-11` / `testnet-12` |
| `KASPA_ACCOUNT_INDEX` | `0` | BIP44 account index |
| `KASPA_MNEMONIC` |  | BIP39 phrase (alternative to encrypted file) |
| `KASPA_PRIVATE_KEY` |  | Raw hex private key (unsaveable) |
| `KASPA_WALLET_PASSWORD` |  | Wallet password for headless setups. **Less preferred than TTY** — leaks via shell history / process inspection. |

### Capability gates (all default OFF)

| Variable | Effect |
|---|---|
| `KASPA_ENABLE_HTTP=1` | Enables the HTTP transport. Requires `KASPA_MCP_TOKEN`. |
| `KASPA_ENABLE_SIGNING=1` | Registers `kaspa_send_transaction` + `kaspa_confirm_send_transaction` and triggers startup wallet unlock. |
| `KASPA_ENABLE_WALLET_SETUP=1` | Registers `kaspa_generate_mnemonic` + `kaspa_save_wallet`. Also triggers startup unlock if a wallet file exists. |

### HTTP-specific

| Variable | Default | Notes |
|---|---|---|
| `KASPA_MCP_TOKEN` |  | Bearer token. **Required** when HTTP is enabled. ≥32 chars, ASCII (hex / base64 / base64url). Generate with `openssl rand -hex 32`. |
| `KASPA_ALLOWED_ORIGINS` | *(empty)* | Comma-separated allowlist for `Origin` header. Empty means: any request that sends an `Origin` header is rejected — meant for non-browser clients. |
| `PORT` | `3000` | Loopback bind port. |

### Caps and rate limits

| Variable | Default | Notes |
|---|---|---|
| `KASPA_MAX_SOMPI_PER_TX` | `100_000_000_000` (1000 KAS) | Enforced on **amount + priority fee** (not just amount), inside `buildPreview` and `signAndSubmit`. |
| `KASPA_MAX_PENDING_TX` | `50` | Hard cap on simultaneous unconfirmed previews. |
| `KASPA_HTTP_RATE_CAPACITY` | `60` | HTTP token-bucket burst. Process-global (loopback-only). |
| `KASPA_HTTP_RATE_REFILL_PER_SEC` | `2` | HTTP refill. |
| `KASPA_PREVIEW_RATE_CAPACITY` | `10` | Preview burst (gates `kaspa_send_transaction`). |
| `KASPA_PREVIEW_RATE_REFILL_PER_SEC` | `~0.167` (10/min) | Preview refill. |
| `KASPA_SIGNING_RATE_CAPACITY` | `5` | Signing burst (gates `kaspa_confirm_send_transaction`, fires **before** consuming the pending entry, so a denial doesn't burn the token). |
| `KASPA_SIGNING_RATE_REFILL_PER_SEC` | `~0.083` (5/min) | Signing refill. |

### Test-only — **never set in production**

These exist purely so the in-repo test suite can exercise behavior that's otherwise time- or hardware-dependent. The server emits loud warnings to stderr when any of them are set.

| Variable | Purpose |
|---|---|
| `KASPA_TEST_MOCK_TXSERVICE=1` | Makes `buildPreview` and `signAndSubmit` return canned data **without** touching the Kaspa node. The two-step HTTP integration test uses this to exercise the pending-map singleton without needing a live node. Emits a loud stderr banner on startup. |
| `KASPA_WALLET_UNLOCK_TIMEOUT_MS` | Shortens the 60s TTY-unlock timeout for tests on systems where `/dev/tty` is openable. Emits a stderr warning the first time the override fires. |

## Audit log

Appended to `~/.kaspa-mcp/audit.log` (chmod 600), one JSON object per line.

Events:

| Event | Fields (besides `ts`, `pid`) |
|---|---|
| `wallet_unlocked` | `source` (`env` / `tty`), `network`, `address` |
| `send_preview_created` | `tokenHash` (sha256[:16] of confirm_token), `digest`, `to`, `amountSompi`, `feeSompiEstimate`, `payloadBytes`, `senderAddress`, `expiresAt` |
| `confirm_attempted` | `tokenHash`, `digest`, `approved` (bool), `method` (`elicitation` / `tty`) or `reason` |
| `confirm_submitted` | `tokenHash`, `digest`, `txId`, `fee`, `method` |
| `confirm_failed` | `tokenHash`, `digest`, `reason` |
| `rate_limited` | `layer` (`http` / `preview` / `signing`), `count`, `firstAt`, `lastAt` — **aggregated** over a ~5s window so a denial loop can't drive sync disk writes |
| `pending_cap_reached` | `cap`, `current` |

What's **not** in the audit log:
- Bearer tokens, confirm tokens, mnemonics, seeds, private keys, wallet passwords (defense-in-depth: a central redactor in `audit.ts` scrubs any field whose name contains `password / mnemonic / seed / secret / bearer / auth / private / token`, walking nested objects, with `*Hash` keys exempted as opaque correlation IDs).
- Full transaction payloads — only the byte count.

You are responsible for retention and rotation. The server appends; it doesn't truncate.

## KPM anchor verification

The `kaspa_verify_kpm_anchor` tool parses the on-chain payload format used by KPM:

```
Bytes: "KPM1" (4) || modeByte (1) || hash (32)   = 37 bytes total
modeByte 0x01 = INDIVIDUAL (single event hash)
modeByte 0x02 = MERKLE (Merkle root)
```

Verification flow:

1. KPM anchors data in block B with txid T.
2. Call `kaspa_verify_kpm_anchor` with `blockHash=B`, `transactionId=T`, `expectedHash=X`.
3. The tool fetches B, finds T, parses the KPM payload, returns `verified: true` iff the on-chain hash matches.

## Development

```bash
npm install
npm run build      # tsc → dist/
npm run dev        # watch mode
npm start          # node dist/index.js
```

### Test suites

Ten test files at the repo root. Each spawns its own state and cleans up. Run them all with:

```bash
npm test
```

`npm test`'s `pretest` step runs `tsc` first so a fresh clone (where `dist/` is gitignored) builds before suites import from it. The runner (`run-tests.mjs`) executes each suite in dependency order and **halts on first failure** so a later integration suite never reports green over dirty state. For an ad-hoc subset:

```bash
npm run build && node test-http-security.mjs   # single suite
```

What each covers:

| File | Coverage |
|---|---|
| `test-http-security.mjs` | HTTP middleware: 401/403/413, body cap, host/origin checks, init round-trip, concurrent-init race fix |
| `test-validation.mjs` | Zod schemas: address shape/checksum, hash length, payload cap, sompi cap |
| `test-tx-split.mjs` | `transaction.ts` split: build/sign separation, drift guards, type checks, recipient validation, cap enforcement |
| `test-wallet-unlock.mjs` | Startup unlock: no-flag → no prompt; env-first ordering; wrong-password resilience |
| `test-tool-gates.mjs` | `tools/list` advertising matches `KASPA_ENABLE_SIGNING` / `KASPA_ENABLE_WALLET_SETUP` |
| `test-mnemonic-gen.mjs` | Generate-mnemonic flow: TTY-only display, no plaintext file, address-derived fingerprint, save-but-not-displayed path |
| `test-save-wallet.mjs` | Save flow: empty-schema, env vs TTY password, overwrite refusal, private-key refusal, no password leak |
| `test-confirmations.mjs` | Pending map + approval resolver + two-step handler (all branches), cross-McpServer singleton |
| `test-send-confirm-http.mjs` | Real wire two-request HTTP round-trip: token from request 1 is consumable in request 2 |
| `test-audit-rate-limit.mjs` | Token bucket, audit JSONL + chmod 600, bucketed rate-limit auditing, scrubber depth cap + circular survival, redactor on compound/nested keys |

The legacy `test-wallet.mjs`, `test-full-workflow.mjs`, `test-smoke.mjs`, `test-tn12-wasm.mjs`, `test-v110.mjs`, `test-kasdk.mjs` files predate the hardening pass. Some reference the removed `kaspa_load_wallet` / inline-password flow. They are kept as historical manual smoke tests against a live node; the ten files above are the supported automated suite.

## License

MIT
