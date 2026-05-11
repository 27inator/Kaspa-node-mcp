/**
 * Full smoke test for kaspa-wasm wallet tools.
 *
 * Tests:
 *   1. WASM loads correctly
 *   2. Mnemonic generation (12 and 24 word)
 *   3. Wallet derivation from provided mnemonic
 *   4. Address format validation
 *   5. Private key extraction
 *   6. RPC connection + fee estimation (requires running node)
 *   7. UTXO lookup for derived address (requires running node)
 */

// WebSocket polyfill must come first
import WebSocket from "isomorphic-ws";
globalThis.WebSocket = WebSocket;

import * as kaspa from "kaspa-wasm";

const TEST_MNEMONIC =
  "current else spice fine old often mistake desert autumn damp law float";
const NETWORK = process.env.KASPA_NETWORK || "testnet-11";
const BORSH_ENDPOINT =
  process.env.KASPA_BORSH_ENDPOINT || "ws://127.0.0.1:17210";
const JSON_ENDPOINT =
  process.env.KASPA_ENDPOINT || "ws://localhost:18210";

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

// ── Test 1: WASM loads ────────────────────────────────────────────────
console.log("\n1. WASM loading");
try {
  const {
    PrivateKey,
    Mnemonic,
    XPrv,
    NetworkType,
    Address,
    Generator,
    RpcClient,
    Encoding,
  } = kaspa;
  if (
    PrivateKey &&
    Mnemonic &&
    XPrv &&
    NetworkType &&
    Address &&
    Generator &&
    RpcClient &&
    Encoding
  ) {
    ok("All required WASM exports present");
  } else {
    fail("WASM exports", "One or more exports are undefined");
  }
} catch (e) {
  fail("WASM loading", e.message);
}

// ── Test 2: Mnemonic generation ──────────────────────────────────────
console.log("\n2. Mnemonic generation");
try {
  const m12 = kaspa.Mnemonic.random(12);
  const words12 = m12.phrase.split(" ");
  if (words12.length === 12) ok("12-word mnemonic generated");
  else fail("12-word mnemonic", `Got ${words12.length} words`);
} catch (e) {
  fail("12-word mnemonic", e.message);
}

try {
  const m24 = kaspa.Mnemonic.random(24);
  const words24 = m24.phrase.split(" ");
  if (words24.length === 24) ok("24-word mnemonic generated");
  else fail("24-word mnemonic", `Got ${words24.length} words`);
} catch (e) {
  fail("24-word mnemonic", e.message);
}

// ── Test 3: Wallet derivation from mnemonic ──────────────────────────
console.log("\n3. Wallet derivation from test mnemonic");
let derivedAddress = "";
let privateKey = null;

try {
  const mnemonic = new kaspa.Mnemonic(TEST_MNEMONIC);
  ok("Mnemonic parsed successfully");

  const seed = mnemonic.toSeed();
  ok(`Seed derived (${seed.length} bytes)`);

  const xprv = new kaspa.XPrv(seed);
  ok("XPrv created from seed");

  // BIP44: m/44'/111111'/0'/0/0
  const derived = xprv
    .deriveChild(44, true)
    .deriveChild(111111, true)
    .deriveChild(0, true)
    .deriveChild(0, false)
    .deriveChild(0, false);
  ok("BIP44 derivation path m/44'/111111'/0'/0/0 succeeded");

  privateKey = derived.toPrivateKey();
  ok(`Private key extracted (type: ${typeof privateKey})`);

  const keypair = privateKey.toKeypair();
  ok("Keypair created from private key");

  const networkType = kaspa.NetworkType.Testnet;
  const address = keypair.toAddress(networkType);
  derivedAddress = address.toString();
  ok(`Address derived: ${derivedAddress}`);

  // Validate address format
  if (derivedAddress.startsWith("kaspatest:")) {
    ok("Address has correct testnet prefix");
  } else {
    fail("Address prefix", `Expected 'kaspatest:', got '${derivedAddress.split(":")[0]}:'`);
  }

  // Validate address is parseable
  const parsed = new kaspa.Address(derivedAddress);
  if (parsed.prefix === "kaspatest") {
    ok("Address round-trip parse succeeded");
  } else {
    fail("Address round-trip", "Prefix mismatch after parse");
  }
} catch (e) {
  fail("Wallet derivation", e.message);
}

// ── Test 4: Deterministic derivation ─────────────────────────────────
console.log("\n4. Deterministic derivation check");
try {
  const mnemonic2 = new kaspa.Mnemonic(TEST_MNEMONIC);
  const seed2 = mnemonic2.toSeed();
  const xprv2 = new kaspa.XPrv(seed2);
  const derived2 = xprv2
    .deriveChild(44, true)
    .deriveChild(111111, true)
    .deriveChild(0, true)
    .deriveChild(0, false)
    .deriveChild(0, false);
  const pk2 = derived2.toPrivateKey();
  const addr2 = pk2.toKeypair().toAddress(kaspa.NetworkType.Testnet).toString();

  if (addr2 === derivedAddress) {
    ok("Same mnemonic produces same address (deterministic)");
  } else {
    fail("Deterministic check", `${addr2} !== ${derivedAddress}`);
  }
} catch (e) {
  fail("Deterministic check", e.message);
}

// ── Test 5: Different account index produces different address ───────
console.log("\n5. Account index isolation");
try {
  const mnemonic3 = new kaspa.Mnemonic(TEST_MNEMONIC);
  const seed3 = mnemonic3.toSeed();
  const xprv3 = new kaspa.XPrv(seed3);
  const derivedAlt = xprv3
    .deriveChild(44, true)
    .deriveChild(111111, true)
    .deriveChild(1, true) // account index 1 instead of 0
    .deriveChild(0, false)
    .deriveChild(0, false);
  const addrAlt = derivedAlt
    .toPrivateKey()
    .toKeypair()
    .toAddress(kaspa.NetworkType.Testnet)
    .toString();

  if (addrAlt !== derivedAddress) {
    ok(`Account 1 address differs: ${addrAlt}`);
  } else {
    fail("Account isolation", "Account 0 and 1 produced the same address");
  }
} catch (e) {
  fail("Account isolation", e.message);
}

// ── Test 6: RPC connection + node info ───────────────────────────────
console.log("\n6. RPC connection to node (Borsh endpoint)");
let rpc = null;
try {
  rpc = new kaspa.RpcClient({
    url: BORSH_ENDPOINT,
    encoding: kaspa.Encoding.Borsh,
    networkId: NETWORK,
  });

  await Promise.race([
    rpc.connect({}),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Connection timed out (10s)")), 10000)
    ),
  ]);
  ok(`Connected to Borsh endpoint: ${BORSH_ENDPOINT}`);

  const serverInfo = await rpc.getServerInfo();
  ok(`Server info: synced=${serverInfo.isSynced}, peers=${serverInfo.peerCount ?? "N/A"}`);

  if (serverInfo.isSynced) {
    ok("Node is synced");
  } else {
    fail("Node sync", "Node reports not synced — transactions will fail");
  }
} catch (e) {
  fail("RPC connection", e.message);
}

// ── Test 7: Fee estimation ───────────────────────────────────────────
console.log("\n7. Fee estimation");
if (rpc) {
  try {
    const feeEstimate = await rpc.getFeeEstimate({});
    ok(`Fee estimate received: ${JSON.stringify(feeEstimate).substring(0, 120)}...`);
  } catch (e) {
    fail("Fee estimation", e.message);
  }
} else {
  fail("Fee estimation", "Skipped — no RPC connection");
}

// ── Test 8: UTXO lookup for derived address ──────────────────────────
console.log("\n8. UTXO lookup for derived wallet address");
if (rpc && derivedAddress) {
  try {
    const { entries } = await rpc.getUtxosByAddresses([
      new kaspa.Address(derivedAddress),
    ]);
    const count = entries ? entries.length : 0;
    const balance = entries
      ? entries.reduce((sum, e) => sum + e.amount, 0n)
      : 0n;
    const balanceKas = Number(balance) / 1e8;

    ok(`UTXOs found: ${count}, balance: ${balanceKas} KAS`);

    if (balance > 0n) {
      ok("Wallet is funded — transaction test is possible");
    } else {
      console.log(
        `  \x1b[33m⚠\x1b[0m Wallet has no funds. To test sending, fund: ${derivedAddress}`
      );
    }
  } catch (e) {
    fail("UTXO lookup", e.message);
  }
} else {
  fail("UTXO lookup", "Skipped — no RPC connection or no address");
}

// ── Test 9: Transaction build (dry run, if funded) ───────────────────
console.log("\n9. Transaction build (if wallet has funds)");
if (rpc && derivedAddress && privateKey) {
  try {
    const { entries } = await rpc.getUtxosByAddresses([
      new kaspa.Address(derivedAddress),
    ]);
    const balance = entries
      ? entries.reduce((sum, e) => sum + e.amount, 0n)
      : 0n;

    if (balance > 0n) {
      // Send a tiny amount back to ourselves as a test
      const testAmount = 100000n; // 0.001 KAS

      if (balance < testAmount + 10000n) {
        console.log(
          `  \x1b[33m⚠\x1b[0m Balance too low for test tx (need >0.0011 KAS, have ${Number(balance) / 1e8} KAS)`
        );
      } else {
        // Sort UTXOs
        entries.sort((a, b) => (a.amount > b.amount ? 1 : -1));

        const generator = new kaspa.Generator({
          entries,
          outputs: [{ address: derivedAddress, amount: testAmount }],
          priorityFee: 0n,
          changeAddress: derivedAddress,
          networkId: NETWORK,
        });
        ok("Generator created successfully");

        const pending = await generator.next();
        if (pending) {
          ok("Pending transaction generated");

          await pending.sign([privateKey]);
          ok("Transaction signed successfully");

          // Actually submit the self-send
          const txId = await pending.submit(rpc);
          ok(`Transaction submitted! txId: ${txId}`);

          const summary = generator.summary();
          ok(`Fees: ${Number(summary.fees) / 1e8} KAS, total txs: 1`);
        } else {
          fail("Transaction build", "Generator produced no transaction");
        }
      }
    } else {
      console.log("  \x1b[33m⚠\x1b[0m Skipped — wallet has no funds");
    }
  } catch (e) {
    fail("Transaction build", e.message);
  }
} else {
  fail("Transaction build", "Skipped — prerequisites not met");
}

// ── Cleanup ──────────────────────────────────────────────────────────
if (rpc) {
  try {
    await rpc.disconnect();
  } catch {}
}

// ── Summary ──────────────────────────────────────────────────────────
console.log("\n" + "─".repeat(50));
console.log(
  `Results: \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m`
);
if (failed === 0) {
  console.log("\x1b[32mAll tests passed!\x1b[0m\n");
} else {
  console.log("\x1b[31mSome tests failed — see above for details.\x1b[0m\n");
}
process.exit(failed > 0 ? 1 : 0);
