/**
 * Kaspa wRPC JSON client.
 *
 * Connects to any rusty-kaspa node's wRPC JSON endpoint via WebSocket.
 * Handles the non-standard response format where results come back
 * in the `params` field (not `result` like standard JSON-RPC).
 *
 * Supports mainnet (18110), testnet-10 (18210), testnet-11 (18310),
 * and devnet nodes — just point it at the right endpoint.
 */

import WebSocket from "ws";

export interface WrpcRequest {
  id: number;
  method: string;
  params: Record<string, unknown>;
}

export interface WrpcResponse {
  id: number;
  method: string;
  params?: Record<string, unknown>;
  error?: {
    code: number;
    message: string;
    data: unknown;
  };
}

export interface KaspaClientConfig {
  /** wRPC JSON WebSocket URL, e.g. ws://localhost:18210 */
  endpoint: string;
  /** Connection timeout in ms (default: 10000) */
  connectTimeoutMs?: number;
  /** Per-request timeout in ms (default: 30000) */
  requestTimeoutMs?: number;
  /** Auto-reconnect on disconnect (default: true) */
  autoReconnect?: boolean;
  /** Reconnect delay in ms (default: 3000) */
  reconnectDelayMs?: number;
}

const DEFAULT_CONFIG: Required<Omit<KaspaClientConfig, "endpoint">> = {
  connectTimeoutMs: 10000,
  requestTimeoutMs: 30000,
  autoReconnect: true,
  reconnectDelayMs: 3000,
};

export class KaspaWrpcClient {
  private ws: WebSocket | null = null;
  private requestId = 0;
  private pending = new Map<
    number,
    {
      resolve: (value: Record<string, unknown>) => void;
      reject: (reason: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private config: KaspaClientConfig & Required<Omit<KaspaClientConfig, "endpoint">>;
  private connected = false;
  private reconnecting = false;

  constructor(config: KaspaClientConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  async connect(): Promise<void> {
    if (this.connected && this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Connection to ${this.config.endpoint} timed out after ${this.config.connectTimeoutMs}ms`));
        this.ws?.close();
      }, this.config.connectTimeoutMs);

      this.ws = new WebSocket(this.config.endpoint);

      this.ws.on("open", () => {
        clearTimeout(timer);
        this.connected = true;
        this.reconnecting = false;
        console.error(`[kaspa-mcp] Connected to ${this.config.endpoint}`);
        resolve();
      });

      this.ws.on("message", (data: Buffer) => {
        this.handleMessage(data);
      });

      this.ws.on("close", () => {
        this.connected = false;
        this.rejectAllPending("WebSocket connection closed");
        if (this.config.autoReconnect && !this.reconnecting) {
          this.scheduleReconnect();
        }
      });

      this.ws.on("error", (err: Error) => {
        clearTimeout(timer);
        if (!this.connected) {
          reject(new Error(`Failed to connect to ${this.config.endpoint}: ${err.message}`));
        }
        console.error(`[kaspa-mcp] WebSocket error: ${err.message}`);
      });
    });
  }

  async disconnect(): Promise<void> {
    this.config.autoReconnect = false;
    this.rejectAllPending("Client disconnecting");
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.connected = false;
  }

  isConnected(): boolean {
    return this.connected && this.ws?.readyState === WebSocket.OPEN;
  }

  /**
   * Send an RPC request and wait for the response.
   * Works with any rusty-kaspa wRPC JSON method.
   */
  async request(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    if (!this.isConnected()) {
      await this.connect();
    }

    const id = ++this.requestId;
    const msg: WrpcRequest = { id, method, params };

    return new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Request ${method} (id=${id}) timed out after ${this.config.requestTimeoutMs}ms`));
      }, this.config.requestTimeoutMs);

      this.pending.set(id, { resolve, reject, timer });

      this.ws!.send(JSON.stringify(msg), (err) => {
        if (err) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(new Error(`Failed to send ${method}: ${err.message}`));
        }
      });
    });
  }

  private handleMessage(data: Buffer): void {
    let response: WrpcResponse;
    try {
      response = JSON.parse(data.toString()) as WrpcResponse;
    } catch {
      console.error("[kaspa-mcp] Failed to parse response:", data.toString().substring(0, 200));
      return;
    }

    // rusty-kaspa wRPC uses the same `id` for request/response correlation
    const entry = this.pending.get(response.id);
    if (!entry) {
      // Could be a notification (server-side push) — ignore for now
      return;
    }

    clearTimeout(entry.timer);
    this.pending.delete(response.id);

    if (response.error) {
      entry.reject(new Error(`${response.method}: ${response.error.message}`));
    } else {
      // rusty-kaspa puts response data in `params`, not `result`
      entry.resolve(response.params ?? {});
    }
  }

  private rejectAllPending(reason: string): void {
    for (const [id, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.reject(new Error(reason));
    }
    this.pending.clear();
  }

  private scheduleReconnect(): void {
    if (this.reconnecting) return;
    this.reconnecting = true;
    console.error(`[kaspa-mcp] Reconnecting in ${this.config.reconnectDelayMs}ms...`);
    setTimeout(async () => {
      try {
        await this.connect();
      } catch (err) {
        console.error(`[kaspa-mcp] Reconnect failed: ${(err as Error).message}`);
        this.reconnecting = false;
        this.scheduleReconnect();
      }
    }, this.config.reconnectDelayMs);
  }
}
