/**
 * Run every supported test file in sequence. Halts on first failure.
 *
 * Tests are listed in dependency order — earlier suites cover the
 * scaffolding later ones rely on (policy, validation, tx-split). The
 * audit/rate-limit suite is last because it boots HTTP child processes.
 *
 * Halting on first failure (rather than running all and summarizing) is
 * deliberate: later integration suites may misreport if earlier suites
 * left state dirty, so reading a green "9/10 passed" tail would be
 * misleading.
 */

import { spawnSync } from "node:child_process";

const SUITES = [
  "test-http-security.mjs",
  "test-validation.mjs",
  "test-tx-split.mjs",
  "test-wallet-unlock.mjs",
  "test-tool-gates.mjs",
  "test-mnemonic-gen.mjs",
  "test-save-wallet.mjs",
  "test-confirmations.mjs",
  "test-send-confirm-http.mjs",
  "test-audit-rate-limit.mjs",
];

const t0 = Date.now();
let passed = 0;
let failedSuite = null;

for (const suite of SUITES) {
  process.stdout.write(`\n━━ ${suite} ━━\n`);
  const r = spawnSync("node", [suite], { stdio: "inherit" });
  if (r.status !== 0) {
    failedSuite = suite;
    break; // halt on first failure — later suites may rely on earlier state
  }
  passed++;
}

const seconds = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`\n${"═".repeat(60)}`);
if (failedSuite === null) {
  console.log(`✓ all ${SUITES.length} suites passed in ${seconds}s`);
} else {
  console.log(
    `✗ halted after ${failedSuite} failed (${passed}/${SUITES.length} passed before stop, ${seconds}s)`,
  );
  process.exit(1);
}
