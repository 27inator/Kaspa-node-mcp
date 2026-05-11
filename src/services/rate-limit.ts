/**
 * Tiny in-process token-bucket rate limiter.
 *
 * Two instances are used:
 *   - HTTP bucket: process-global (the server is loopback-only, so per-IP
 *     discrimination is theatre — see README threat model). Sits after
 *     Host/Origin checks and BEFORE bearer auth + JSON parsing so a
 *     denied request never charges parsing work and a token-guessing
 *     attacker can't cheaply spin the bucket.
 *   - Signing bucket: gates kaspa_confirm_send_transaction BEFORE
 *     consumePending() so a rate-limit denial does not burn a valid token.
 *
 * Implementation is single-process. Multiple server processes do not share
 * state; that's fine because we're loopback-only and a multi-process setup
 * is out of scope.
 */

export class TokenBucket {
  private tokens: number;
  private lastRefill: number;
  // Capacity and refill rate are mutable to support _reconfigureForTests.
  // Production code only sets them via the constructor.
  private capacity: number;
  private refillPerSecond: number;

  constructor(capacity: number, refillPerSecond: number) {
    this.capacity = capacity;
    this.refillPerSecond = refillPerSecond;
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  /**
   * Try to consume one token. Returns true on success, false if the bucket
   * is empty. Refill is computed lazily on each call so we don't need a
   * background timer (one fewer interval pinning the event loop).
   */
  consume(): boolean {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  /** Current token count after refill — exposed for tests. */
  peek(): number {
    this.refill();
    return this.tokens;
  }

  private refill(): void {
    const now = Date.now();
    const elapsedSec = (now - this.lastRefill) / 1000;
    if (elapsedSec <= 0) return;
    this.tokens = Math.min(
      this.capacity,
      this.tokens + elapsedSec * this.refillPerSecond,
    );
    this.lastRefill = now;
  }

  /** Test affordance: drain the bucket. */
  _drainForTests(): void {
    this.tokens = 0;
    this.lastRefill = Date.now();
  }

  /**
   * Test affordance: reconfigure capacity/refill, draining the bucket.
   * Needed when a parent test sets a high refill rate (so unrelated test
   * sections don't starve) but one specific section wants to exercise
   * actual rate limiting — `_drainForTests` alone is insufficient because
   * even microseconds of elapsed time at a high refill rate immediately
   * re-fills the bucket.
   */
  _reconfigureForTests(capacity: number, refillPerSecond: number): void {
    this.capacity = capacity;
    this.refillPerSecond = refillPerSecond;
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }
}
