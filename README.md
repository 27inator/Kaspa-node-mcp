# kaspa-node-mcp-server

Read-only MCP server for interacting with any [rusty-kaspa](https://github.com/kaspanet/rusty-kaspa) node via wRPC JSON over WebSocket.

Gives AI agents (Claude Code, OpenClaw, etc.) the ability to independently query and verify data on the Kaspa blockchain — including verifying KPM Pharma anchor transactions.

## Features

- **Any network**: works with mainnet, testnet-10, testnet-11, devnet
- **Read-only**: never submits transactions or modifies node state
- **KPM-aware**: automatically parses KPM anchor payloads (`KPM1 || mode || hash`)
- **Two transports**: stdio (for Claude Code) or HTTP (for OpenClaw / remote)
- **Auto-reconnect**: recovers from node restarts and network blips

## Tools

| Tool | Purpose |
|------|---------|
| `kaspa_get_info` | Node health check (sync status, version, mempool) |
| `kaspa_get_server_info` | Network ID, API version, DAA score |
| `kaspa_get_block_dag_info` | Chain state (tips, difficulty, block count) |
| `kaspa_get_block` | Fetch block by hash with optional transactions |
| `kaspa_get_balance` | Address balance in sompi and KAS |
| `kaspa_get_utxos` | UTXO set for addresses |
| `kaspa_find_transaction_in_block` | Find and parse a tx in a specific block |
| `kaspa_search_blocks_for_transaction` | Search recent blocks for a tx by ID |
| `kaspa_verify_kpm_anchor` | Verify a KPM anchor payload on-chain |
| `kaspa_get_coin_supply` | Circulating and max supply |

## Prerequisites

- Node.js 18+
- A running rusty-kaspa node with `--rpclisten-json` enabled

Your node must be started with the wRPC JSON flag:

```bash
# Testnet
./kaspad --testnet --utxoindex --rpclisten-json=0.0.0.0:18210

# Mainnet
./kaspad --utxoindex --rpclisten-json=0.0.0.0:18110
```

## Install

```bash
git clone https://github.com/YOUR_ORG/kaspa-node-mcp-server.git
cd kaspa-node-mcp-server
npm install
npm run build
```

## Usage

### With Claude Code (stdio)

Add to your `.claude/settings.json`:

```json
{
  "mcpServers": {
    "kaspa-node": {
      "command": "node",
      "args": ["/path/to/kaspa-node-mcp-server/dist/index.js"],
      "env": {
        "KASPA_ENDPOINT": "ws://localhost:18210"
      }
    }
  }
}
```

### With OpenClaw (HTTP)

```bash
KASPA_ENDPOINT=ws://localhost:18210 TRANSPORT=http PORT=3001 node dist/index.js
```

Then register in OpenClaw as an MCP endpoint at `http://localhost:3001/mcp`.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KASPA_ENDPOINT` | `ws://localhost:18210` | wRPC JSON WebSocket URL |
| `TRANSPORT` | `stdio` | Transport mode: `stdio` or `http` |
| `PORT` | `3000` | HTTP port (only used with `http` transport) |

## Common Ports by Network

| Network | wRPC JSON Port | Example Endpoint |
|---------|---------------|------------------|
| Mainnet | 18110 | `ws://localhost:18110` |
| Testnet-10 | 18210 | `ws://localhost:18210` |
| Testnet-11 | 18310 | `ws://localhost:18310` |

## KPM Anchor Verification

The `kaspa_verify_kpm_anchor` tool parses KPM's on-chain payload format:

```
Bytes: "KPM1" (4 bytes) || modeByte (1 byte) || hash (32 bytes)
Total: 37 bytes

modeByte 0x01 = INDIVIDUAL (payload contains a single event hash)
modeByte 0x02 = MERKLE (payload contains a Merkle root)
```

Example verification flow:
1. KPM says event X is anchored in block B with txid T
2. Call `kaspa_verify_kpm_anchor` with blockHash=B, transactionId=T, expectedHash=X
3. Tool fetches the block, finds the tx, parses the KPM payload
4. Returns `verified: true` if the on-chain hash matches

## Development

```bash
npm run dev    # Watch mode for TypeScript
npm run build  # Build to dist/
npm start      # Run built server
```

## License

MIT
