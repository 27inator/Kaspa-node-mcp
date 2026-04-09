/**
 * WebSocket polyfill for Node.js environment.
 *
 * kaspa-wasm's RpcClient expects a W3C WebSocket on globalThis.
 * This MUST be imported before any kaspa-wasm usage.
 */

import WebSocket from "isomorphic-ws";
(globalThis as unknown as { WebSocket: typeof WebSocket }).WebSocket = WebSocket;
