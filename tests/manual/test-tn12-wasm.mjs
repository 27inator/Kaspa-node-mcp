/**
 * Full test suite for kaspa-wasm built from the tn12 branch.
 * Tests: WASM loading, wallet derivation, RPC, fees, UTXOs, Generator, signing, submission.
 */
import WebSocket from "isomorphic-ws";
globalThis.WebSocket = WebSocket;

import { createRequire } from "module";
const require = createRequire(import.meta.url);
const kaspa = require("./vendor/kaspa-wasm/kaspa");

const TEST_MNEMONIC =
  "current else spice fine old often mistake desert autumn damp law float";
const NETWORK = "testnet-12";
const BORSH_ENDPOINT = "ws://127.0.0.1:17210";

let passed = 0;
let failed = 0;

function ok(label) {
  passed++;
  console.log(`  \x1b[32m✓\x1b[0m ${label}`);
}
function fail(label, err) {
  failed++;
  console.log(`  \x1b[31m✗\x1b[0m ${label}: ${err}`);
}

// ── 1: WASM loading ──────────────────────────────────────────────────
console.log("\n1. WASM loading (tn12 branch build)");
try {
  if (kaspa.initConsolePanicHook) {
    kaspa.initConsolePanicHook();
    ok("initConsolePanicHook enabled");
  }
  const needed = [
    "PrivateKey", "Mnemonic", "XPrv", "NetworkType", "Address",
    "Generator", "RpcClient", "Encoding", "NetworkId",
  ];
  const missing = needed.filter((n) => !kaspa[n]);
  if (missing.length === 0) {
    ok(`All required exports present (${Object.keys(kaspa).filter(k => !k.startsWith("__")).length} total)`);
  } else {
    fail("WASM exports", `Missing: ${missing.join(", ")}`);
  }
} catch (e) {
  fail("WASM loading", e.message);
}

// ── 2: NetworkId for testnet-12 ─────────────────────────────────────
console.log("\n2. NetworkId testnet-12 support");
try {
  const nid = new kaspa.NetworkId(NETWORK);
  ok(`NetworkId('testnet-12') created: ${nid.toString()}`);
} catch (e) {
  fail("NetworkId", e.message);
}

// ── 3: Mnemonic generation ──────────────────────────────────────────
console.log("\n3. Mnemonic generation");
try {
  const m12 = kaspa.Mnemonic.random(12);
  if (m12.phrase.split(" ").length === 12) ok("12-word mnemonic");
  else fail("12-word", `Got ${m12.phrase.split(" ").length} words`);
} catch (e) { fail("12-word mnemonic", e.message); }

try {
  const m24 = kaspa.Mnemonic.random(24);
  if (m24.phrase.split(" ").length === 24) ok("24-word mnemonic");
  else fail("24-word", `Got ${m24.phrase.split(" ").length} words`);
} catch (e) { fail("24-word mnemonic", e.message); }

// ── 4: Wallet derivation ────────────────────────────────────────────
console.log("\n4. Wallet derivation from test mnemonic");
let derivedAddress = "";
let privateKey = null;

try {
  const mnemonic = new kaspa.Mnemonic(TEST_MNEMONIC);
  ok("Mnemonic parsed");

  const seed = mnemonic.toSeed();
  ok(`Seed derived (${seed.length} bytes)`);

  const xprv = new kaspa.XPrv(seed);
  const derived = xprv
    .deriveChild(44, true)
    .deriveChild(111111, true)
    .deriveChild(0, true)
    .deriveChild(0, false)
    .deriveChild(0, false);
  ok("BIP44 path m/44'/111111'/0'/0/0 derived");

  privateKey = derived.toPrivateKey();
  const keypair = privateKey.toKeypair();
  const address = keypair.toAddress(kaspa.NetworkType.Testnet);
  derivedAddress = address.toString();
  ok(`Address: ${derivedAddress}`);

  if (derivedAddress.startsWith("kaspatest:")) {
    ok("Correct testnet prefix");
  } else {
    fail("Prefix", `Expected kaspatest:, got ${derivedAddress.split(":")[0]}:`);
  }

  // Round-trip
  const parsed = new kaspa.Address(derivedAddress);
  if (parsed.prefix === "kaspatest") ok("Address round-trip OK");
  else fail("Round-trip", "prefix mismatch");
} catch (e) {
  fail("Wallet derivation", e.message);
}

// ── 5: Deterministic check ──────────────────────────────────────────
console.log("\n5. Deterministic derivation");
try {
  const m2 = new kaspa.Mnemonic(TEST_MNEMONIC);
  const s2 = m2.toSeed();
  const x2 = new kaspa.XPrv(s2);
  const d2 = x2.deriveChild(44,true).deriveChild(111111,true).deriveChild(0,true).deriveChild(0,false).deriveChild(0,false);
  const a2 = d2.toPrivateKey().toKeypair().toAddress(kaspa.NetworkType.Testnet).toString();
  if (a2 === derivedAddress) ok("Same mnemonic → same address");
  else fail("Deterministic", `${a2} !== ${derivedAddress}`);
} catch (e) { fail("Deterministic", e.message); }

// ── 6: Account isolation ────────────────────────────────────────────
console.log("\n6. Account index isolation");
try {
  const m3 = new kaspa.Mnemonic(TEST_MNEMONIC);
  const s3 = m3.toSeed();
  const x3 = new kaspa.XPrv(s3);
  const d3 = x3.deriveChild(44,true).deriveChild(111111,true).deriveChild(1,true).deriveChild(0,false).deriveChild(0,false);
  const a3 = d3.toPrivateKey().toKeypair().toAddress(kaspa.NetworkType.Testnet).toString();
  if (a3 !== derivedAddress) ok(`Account 1 differs: ${a3}`);
  else fail("Isolation", "Same address for account 0 and 1");
} catch (e) { fail("Isolation", e.message); }

// ── 7: RPC connection ───────────────────────────────────────────────
console.log("\n7. RPC connection (Borsh endpoint)");
let rpc = null;
try {
  rpc = new kaspa.RpcClient({
    url: BORSH_ENDPOINT,
    encoding: kaspa.Encoding.Borsh,
    networkId: NETWORK,
  });
  await Promise.race([
    rpc.connect({}),
    new Promise((_, rej) => setTimeout(() => rej(new Error("Timeout 10s")), 10000)),
  ]);
  ok(`Connected to ${BORSH_ENDPOINT}`);

  const info = await rpc.getServerInfo();
  ok(`Synced: ${info.isSynced}, peers: ${info.peerCount ?? "N/A"}`);
  if (info.isSynced) ok("Node is synced");
  else fail("Sync", "Node not synced");
} catch (e) { fail("RPC connection", e.message); }

// ── 8: Fee estimation ───────────────────────────────────────────────
console.log("\n8. Fee estimation");
if (rpc) {
  try {
    const fee = await rpc.getFeeEstimate({});
    ok(`Fee estimate: ${JSON.stringify(fee).substring(0, 120)}...`);
  } catch (e) { fail("Fee estimation", e.message); }
} else { fail("Fee estimation", "No RPC"); }

// ── 9: UTXO lookup ─────────────────────────────────────────────────
console.log("\n9. UTXO lookup");
let entries = [];
let balance = 0n;
if (rpc && derivedAddress) {
  try {
    const result = await rpc.getUtxosByAddresses([new kaspa.Address(derivedAddress)]);
    entries = result.entries || [];
    balance = entries.reduce((s, e) => s + e.amount, 0n);
    ok(`UTXOs: ${entries.length}, balance: ${Number(balance) / 1e8} KAS`);
    if (balance > 0n) ok("Wallet is funded");
    else console.log(`  \x1b[33m⚠\x1b[0m No funds — fund ${derivedAddress}`);
  } catch (e) { fail("UTXO lookup", e.message); }
} else { fail("UTXO lookup", "No RPC or address"); }

// ── 10: Generator + sign + submit (self-send) ──────────────────────
console.log("\n10. Transaction: Generator → sign → submit");
if (rpc && derivedAddress && privateKey && balance > 0n) {
  try {
    entries.sort((a, b) => (a.amount > b.amount ? 1 : -1));

    const testAmount = 1000000000n; // 10 KAS (TN12 storage mass requires larger outputs)
    if (balance < testAmount + 100000n) {
      console.log(`  \x1b[33m⚠\x1b[0m Balance too low (need >10 KAS)`);
    } else {
      const generator = new kaspa.Generator({
        entries,
        outputs: [{ address: derivedAddress, amount: testAmount }],
        priorityFee: 0n,
        changeAddress: derivedAddress,
        networkId: NETWORK,
      });
      ok("Generator created");

      const pending = await generator.next();
      if (pending) {
        ok("Pending transaction generated");

        await pending.sign([privateKey]);
        ok("Transaction signed");

        const txId = await pending.submit(rpc);
        ok(`Transaction submitted! txId: ${txId}`);

        const summary = generator.summary();
        ok(`Fees: ${Number(summary.fees) / 1e8} KAS`);
      } else {
        fail("Generator", "No pending transaction produced");
      }
    }
  } catch (e) {
    fail("Transaction", e.message);
  }
} else {
  if (balance === 0n) console.log("  \x1b[33m⚠\x1b[0m Skipped — no funds");
  else fail("Transaction", "Prerequisites not met");
}

// ── Cleanup ─────────────────────────────────────────────────────────
if (rpc) { try { await rpc.disconnect(); } catch {} }

// ── Summary ─────────────────────────────────────────────────────────
console.log("\n" + "─".repeat(55));
console.log(`Results: \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m`);
if (failed === 0) console.log("\x1b[32mAll tests passed!\x1b[0m\n");
else console.log("\x1b[31mSome tests failed.\x1b[0m\n");
process.exit(failed > 0 ? 1 : 0);
