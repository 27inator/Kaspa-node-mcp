/**
 * Smoke test for wallet + node integration on TN12.
 * Run: node test-smoke.mjs
 */

// WebSocket polyfill must come first
import WebSocket from "isomorphic-ws";
globalThis.WebSocket = WebSocket;

import * as kaspa from "kaspa-wasm";

const { Mnemonic, XPrv, PrivateKey, NetworkType, RpcClient, Encoding, Generator, Address, sompiToKaspaString } = kaspa;

const MNEMONIC = "current else spice fine old often mistake desert autumn damp law float";
const NETWORK = "testnet-12";
const BORSH_ENDPOINT = "ws://127.0.0.1:17210";
const JSON_ENDPOINT = "ws://127.0.0.1:18210";

// ── Step 1: Wallet derivation ──────────────────────────────────────────
console.log("=== Step 1: Wallet Derivation ===");
try {
  const mnemonic = new Mnemonic(MNEMONIC);
  const seed = mnemonic.toSeed();
  const xprv = new XPrv(seed);

  const derived = xprv
    .deriveChild(44, true)
    .deriveChild(111111, true)
    .deriveChild(0, true)
    .deriveChild(0, false)
    .deriveChild(0, false);

  const privateKey = derived.toPrivateKey();
  const keypair = privateKey.toKeypair();
  const address = keypair.toAddress(NetworkType.Testnet).toString();

  console.log("  Address:", address);
  console.log("  PASS: WASM loaded, mnemonic derived successfully\n");

  // ── Step 2: Connect via Borsh RPC ────────────────────────────────────
  console.log("=== Step 2: Borsh RPC Connection ===");
  const rpc = new RpcClient({
    url: BORSH_ENDPOINT,
    encoding: Encoding.Borsh,
    networkId: NETWORK,
  });

  await rpc.connect({});
  console.log("  PASS: Connected to Borsh endpoint\n");

  // ── Step 3: Node info ────────────────────────────────────────────────
  console.log("=== Step 3: Node Info ===");
  const serverInfo = await rpc.getServerInfo();
  console.log("  Network ID:", serverInfo.networkId);
  console.log("  Synced:", serverInfo.isSynced);
  console.log("  Version:", serverInfo.serverVersion);
  console.log("  PASS: Node info retrieved\n");

  // ── Step 4: Balance check ────────────────────────────────────────────
  console.log("=== Step 4: Balance Check ===");
  const { entries } = await rpc.getUtxosByAddresses([new Address(address)]);
  const totalBalance = entries.reduce((sum, e) => sum + e.amount, 0n);
  console.log("  UTXOs:", entries.length);
  console.log("  Balance:", sompiToKaspaString(totalBalance), "KAS");
  console.log("  PASS: Balance retrieved\n");

  // ── Step 5: Self-send test (only if balance > 0) ─────────────────────
  if (totalBalance > 0n) {
    console.log("=== Step 5: Self-Send Transaction ===");
    const sendAmount = 100000000n; // 1 KAS

    if (totalBalance < sendAmount) {
      console.log("  SKIP: Balance too low for test send\n");
    } else {
      entries.sort((a, b) => (a.amount > b.amount ? 1 : -1));

      const generator = new Generator({
        entries,
        outputs: [{ address, amount: sendAmount }],
        priorityFee: 0n,
        changeAddress: address,
        networkId: NETWORK,
      });

      let pending;
      let lastTxId = "";
      let txCount = 0;

      while ((pending = await generator.next())) {
        await pending.sign([privateKey]);
        const txId = await pending.submit(rpc);
        lastTxId = txId;
        txCount++;
        console.log("  Submitted TX:", txId);
      }

      const summary = generator.summary();
      console.log("  Fee:", sompiToKaspaString(summary.fees), "KAS");
      console.log("  Total TXs:", txCount);
      console.log("  PASS: Self-send transaction succeeded\n");
    }
  } else {
    console.log("=== Step 5: Self-Send Transaction ===");
    console.log("  SKIP: No balance to test with\n");
  }

  await rpc.disconnect();
  console.log("=== ALL TESTS PASSED ===");

} catch (error) {
  console.error("\nFAIL:", error.message || error);
  process.exit(1);
}
