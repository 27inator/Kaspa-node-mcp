/**
 * Kaspa wRPC Borsh client.
 *
 * Wraps kaspa-wasm's RpcClient with Borsh encoding to communicate
 * with any rusty-kaspa node's Borsh wRPC endpoint (--rpclisten-borsh).
 * No JSON wRPC endpoint (--rpclisten-json) is needed.
 *
 * Network-agnostic: works with mainnet, testnet-10, testnet-11,
 * testnet-12, devnet — just point it at the right endpoint.
 */

import * as kaspa from "kaspa-wasm";

const { RpcClient, Encoding } = kaspa;

export interface KaspaClientConfig {
  /** wRPC Borsh WebSocket URL, e.g. ws://127.0.0.1:17210 */
  endpoint: string;
  /** Optional network ID (e.g. "mainnet", "testnet-10", "testnet-12"). Auto-detected if omitted. */
  networkId?: string;
  /** Connection timeout in ms (default: 10000) */
  connectTimeoutMs?: number;
  /** Per-request timeout in ms (default: 30000) */
  requestTimeoutMs?: number;
}

/**
 * Recursively convert WASM response objects to plain JSON-serializable objects.
 * Converts bigint values to numbers for JSON.stringify compatibility.
 */
function toPlainObject(value: unknown): unknown {
  if (typeof value === "bigint") {
    return Number(value);
  }
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(toPlainObject);
  }
  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      result[key] = toPlainObject(val);
    }
    return result;
  }
  return value;
}

export class KaspaWrpcClient {
  private rpc: kaspa.RpcClient;
  private config: KaspaClientConfig & { connectTimeoutMs: number; requestTimeoutMs: number };
  private connected = false;

  constructor(config: KaspaClientConfig) {
    this.config = {
      connectTimeoutMs: 10000,
      requestTimeoutMs: 30000,
      ...config,
    };

    const rpcConfig: kaspa.IRpcConfig = {
      url: this.config.endpoint,
      encoding: Encoding.Borsh,
    };
    if (this.config.networkId) {
      rpcConfig.networkId = this.config.networkId;
    }
    this.rpc = new RpcClient(rpcConfig);
  }

  async connect(): Promise<void> {
    if (this.connected) return;

    await Promise.race([
      this.rpc.connect({}),
      new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error(
            `Connection to ${this.config.endpoint} timed out after ${this.config.connectTimeoutMs}ms`
          )),
          this.config.connectTimeoutMs,
        )
      ),
    ]);
    this.connected = true;
    console.error(`[kaspa-mcp] Connected to ${this.config.endpoint} (Borsh)`);
  }

  async disconnect(): Promise<void> {
    this.connected = false;
    try {
      await this.rpc.disconnect();
    } catch {
      // ignore disconnect errors
    }
  }

  isConnected(): boolean {
    return this.connected;
  }

  /**
   * Send an RPC request and wait for the response.
   * Maps method names to kaspa-wasm RpcClient methods.
   */
  async request(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    if (!this.connected) {
      await this.connect();
    }

    const fn = (this.rpc as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>)[method];
    if (typeof fn !== "function") {
      throw new Error(`Unknown RPC method: ${method}`);
    }

    const hasParams = Object.keys(params).length > 0;

    const result = await Promise.race([
      fn.call(this.rpc, hasParams ? params : undefined),
      new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error(`Request ${method} timed out after ${this.config.requestTimeoutMs}ms`)),
          this.config.requestTimeoutMs,
        )
      ),
    ]);

    return toPlainObject(result) as Record<string, unknown>;
  }
}
