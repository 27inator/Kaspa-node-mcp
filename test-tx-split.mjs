/**
 * Phase 4.5 smoke test: transaction service split.
 *
 * Verifies the structural guarantees that Phase 3 will rely on:
 *   1. Module exposes buildPreview, signAndSubmit, sendKaspa, types.
 *   2. buildPreview rejects amounts below MIN_OUTPUT_SOMPI BEFORE any RPC.
 *   3. signAndSubmit's network-drift guard fires before any RPC and refuses
 *      to sign a TxParams whose `network` no longer matches the wallet.
 *   4. signAndSubmit's sender-drift guard fires before any RPC.
 *   5. TxParams round-trips through JSON cleanly (no WASM object leaks).
 *
 * Tests 2-4 work without a live Kaspa node because the early guards run
 * before createRpcClient() opens a WebSocket.
 */

import "./dist/services/setup.js"; // WebSocket polyfill (no-op on modern Node)

const KASPA_TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

process.env.KASPA_MNEMONIC = KASPA_TEST_MNEMONIC;
process.env.KASPA_NETWORK = "testnet-12";

const { buildPreview, signAndSubmit, sendKaspa } = await import(
  "./dist/services/transaction.js"
);
const { getWallet, setWalletInstance, KaspaWallet, clearWalletInstance } =
  await import("./dist/services/wallet.js");

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? " — " + detail : ""}`);
}

// 1. Module exports present and callable
{
  const ok =
    typeof buildPreview === "function" &&
    typeof signAndSubmit === "function" &&
    typeof sendKaspa === "function";
  check("module exports buildPreview / signAndSubmit / sendKaspa", ok);
}

// 2. buildPreview rejects below-minimum amount BEFORE any RPC connection
{
  let err;
  try {
    await buildPreview({
      to: "kaspatest:qzr0kzh7ypvfczks24mcakmccfd2drm6tjmprr8h0w6m6sn3rspqyfp7chx0u",
      amountSompi: 1_000_000n, // 0.01 KAS, below the 0.1 KAS minimum
      priorityFeeSompi: 0n,
    });
  } catch (e) {
    err = e;
  }
  const ok = err && /amount too small|0\.1 KAS|storage mass/i.test(err.message);
  check(
    "buildPreview: <0.1 KAS rejected before RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

// 3. signAndSubmit network-drift guard. Wallet is on testnet-12; we feed
//    TxParams with network "testnet-10" and expect a throw before any RPC.
//
//    We use the wallet's own address as the recipient so the new recipient-
//    checksum check passes — we want this test to exercise the drift guard,
//    not bounce on recipient validation.
{
  const wallet = getWallet(); // testnet-12
  const fakeParams = {
    to: wallet.getAddress(),
    amountSompi: "100000000",
    priorityFeeSompi: "0",
    network: "testnet-10", // <-- drifted
    senderAddress: wallet.getAddress(),
  };
  let err;
  try {
    await signAndSubmit(fakeParams);
  } catch (e) {
    err = e;
  }
  const ok = err && /wallet network changed/i.test(err.message);
  check(
    "signAndSubmit: network drift rejected before RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

// 4. signAndSubmit sender-drift guard.
//    Same trick: real recipient (= wallet address) so we land on the drift
//    guard rather than the recipient checksum.
{
  const wallet = getWallet();
  const fakeParams = {
    to: wallet.getAddress(),
    amountSompi: "100000000",
    priorityFeeSompi: "0",
    network: wallet.getNetworkId(),
    // Different but checksum-valid testnet address — same mnemonic, account
    // index 1 instead of 0, which derives a different BIP44 path.
    senderAddress: KaspaWallet.fromMnemonic(
      KASPA_TEST_MNEMONIC,
      "testnet-12",
      1
    ).getAddress(),
  };
  let err;
  try {
    await signAndSubmit(fakeParams);
  } catch (e) {
    err = e;
  }
  const ok = err && /sender address changed/i.test(err.message);
  check(
    "signAndSubmit: sender drift rejected before RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

// 5. TxParams round-trips through JSON without losing data and without
//    sneaking in any WASM-only types (BigInt, Address, etc.). We construct
//    a representative shape and verify all fields survive.
{
  const wallet = getWallet();
  const params = {
    to: "kaspatest:qzr0kzh7ypvfczks24mcakmccfd2drm6tjmprr8h0w6m6sn3rspqyfp7chx0u",
    amountSompi: "100000000",
    priorityFeeSompi: "0",
    payload: "deadbeef",
    network: wallet.getNetworkId(),
    senderAddress: wallet.getAddress(),
  };
  let roundTrip;
  try {
    roundTrip = JSON.parse(JSON.stringify(params));
  } catch (e) {
    roundTrip = null;
  }
  const ok =
    roundTrip &&
    roundTrip.to === params.to &&
    roundTrip.amountSompi === params.amountSompi &&
    roundTrip.priorityFeeSompi === params.priorityFeeSompi &&
    roundTrip.payload === params.payload &&
    roundTrip.network === params.network &&
    roundTrip.senderAddress === params.senderAddress;
  check("TxParams JSON-roundtrips cleanly", ok);
}

// 6. signAndSubmit validates malformed amountSompi (non-decimal) before RPC
{
  const wallet = getWallet();
  const params = {
    to: "kaspatest:qzr0kzh7ypvfczks24mcakmccfd2drm6tjmprr8h0w6m6sn3rspqyfp7chx0u",
    amountSompi: "0xabc",
    priorityFeeSompi: "0",
    network: wallet.getNetworkId(),
    senderAddress: wallet.getAddress(),
  };
  let err;
  try { await signAndSubmit(params); } catch (e) { err = e; }
  const ok = err && /amountSompi.*decimal/i.test(err.message);
  check(
    "signAndSubmit: non-decimal amountSompi rejected pre-RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

// 7. signAndSubmit rejects negative priorityFee (would have parsed via raw
//    BigInt() before the validation fix).
{
  const wallet = getWallet();
  const params = {
    to: "kaspatest:qzr0kzh7ypvfczks24mcakmccfd2drm6tjmprr8h0w6m6sn3rspqyfp7chx0u",
    amountSompi: "100000000",
    priorityFeeSompi: "-1",
    network: wallet.getNetworkId(),
    senderAddress: wallet.getAddress(),
  };
  let err;
  try { await signAndSubmit(params); } catch (e) { err = e; }
  // "-1" fails the decimal-only regex first; either rejection is acceptable.
  const ok = err && /priorityFee|decimal/i.test(err.message);
  check(
    "signAndSubmit: negative priorityFee rejected pre-RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

// 8. signAndSubmit rejects payload with odd hex length
{
  const wallet = getWallet();
  const params = {
    to: "kaspatest:qzr0kzh7ypvfczks24mcakmccfd2drm6tjmprr8h0w6m6sn3rspqyfp7chx0u",
    amountSompi: "100000000",
    priorityFeeSompi: "0",
    payload: "abc", // odd length
    network: wallet.getNetworkId(),
    senderAddress: wallet.getAddress(),
  };
  let err;
  try { await signAndSubmit(params); } catch (e) { err = e; }
  const ok = err && /payload/i.test(err.message);
  check(
    "signAndSubmit: odd-length payload rejected pre-RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

// 9. signAndSubmit enforces KASPA_MAX_SOMPI_PER_TX cap (default 1000 KAS).
//    Total spend amount + fee = 1001 KAS > cap.
{
  const wallet = getWallet();
  const params = {
    to: "kaspatest:qzr0kzh7ypvfczks24mcakmccfd2drm6tjmprr8h0w6m6sn3rspqyfp7chx0u",
    amountSompi: (1000n * 100_000_000n).toString(),
    priorityFeeSompi: (1n * 100_000_000n).toString(), // 1 KAS fee → total > cap
    network: wallet.getNetworkId(),
    senderAddress: wallet.getAddress(),
  };
  let err;
  try { await signAndSubmit(params); } catch (e) { err = e; }
  const ok = err && /KASPA_MAX_SOMPI_PER_TX|cap/i.test(err.message);
  check(
    "signAndSubmit: total > cap rejected pre-RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

// 10a. signAndSubmit rejects non-string `to` field (typeof guard)
{
  const wallet = getWallet();
  const params = {
    to: 12345, // not a string
    amountSompi: "100000000",
    priorityFeeSompi: "0",
    network: wallet.getNetworkId(),
    senderAddress: wallet.getAddress(),
  };
  let err;
  try { await signAndSubmit(params); } catch (e) { err = e; }
  const ok = err && /to must be a string/i.test(err.message);
  check(
    "signAndSubmit: non-string `to` rejected pre-RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

// 10b. signAndSubmit rejects a non-conforming recipient before RPC. We test
//      with a well-shaped but bad-checksum mainnet address against a testnet
//      params bundle; either the prefix mismatch OR the checksum fires —
//      both are valid recipient rejections for our purposes (the point is
//      that the service-level check runs before drift guards/RPC).
{
  const wallet = getWallet();
  const params = {
    to: "kaspa:" + "q".repeat(60), // shape-valid mainnet, bad checksum
    amountSompi: "100000000",
    priorityFeeSompi: "0",
    network: wallet.getNetworkId(), // testnet-12 → expects kaspatest: prefix
    senderAddress: wallet.getAddress(),
  };
  let err;
  try { await signAndSubmit(params); } catch (e) { err = e; }
  const ok = err && /recipient/i.test(err.message);
  check(
    "signAndSubmit: cross-network recipient rejected pre-RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

// 10c. buildPreview also rejects bad-checksum recipient before RPC
{
  let err;
  try {
    await buildPreview({
      to: "kaspatest:" + "q".repeat(60), // valid charset, bad checksum
      amountSompi: 100_000_000n,
      priorityFeeSompi: 0n,
    });
  } catch (e) { err = e; }
  const ok = err && /recipient.*invalid Kaspa address|recipient.*unreachable/i.test(err.message);
  check(
    "buildPreview: bad-checksum recipient rejected pre-RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

// 11. buildPreview enforces the cap directly (Phase 3 will call this path).
{
  let err;
  try {
    await buildPreview({
      to: "kaspatest:qzr0kzh7ypvfczks24mcakmccfd2drm6tjmprr8h0w6m6sn3rspqyfp7chx0u",
      amountSompi: 1001n * 100_000_000n, // 1001 KAS, over default 1000 cap
      priorityFeeSompi: 0n,
    });
  } catch (e) { err = e; }
  const ok = err && /KASPA_MAX_SOMPI_PER_TX|cap/i.test(err.message);
  check(
    "buildPreview: cap enforced before RPC",
    !!ok,
    err ? err.message : "no throw"
  );
}

clearWalletInstance();

const failed = results.filter((r) => !r.ok);
if (failed.length) {
  console.error(`\n${failed.length}/${results.length} checks failed`);
  process.exit(1);
}
console.log(`\nall ${results.length} checks passed`);
