# kaspa-node-mcp

MCP server for interacting with any [rusty-kaspa](https://github.com/kaspanet/rusty-kaspa) node via wRPC Borsh over WebSocket.

Gives AI agents (Claude Code, OpenClaw, etc.) the ability to query the Kaspa blockchain, manage wallets, and submit transactions — including anchoring and verifying KPM payloads on-chain.

## Features

- **Any network**: mainnet, testnet-10, testnet-11, testnet-12, devnet
- **Full wallet**: BIP39 mnemonic generation, BIP44 derivation, encrypted persistence
- **Transactions**: build, sign, and submit via WASM Generator (KIP-9 compliant)
- **KPM-aware**: automatically parses KPM anchor payloads (`KPM1 || mode || hash`)
- **Encrypted wallet**: AES-256-GCM with scrypt KDF, stored at `~/.kaspa-mcp/wallet.enc`
- **Two transports**: stdio (Claude Code) or HTTP (OpenClaw / remote)
- **Lazy connection**: server starts instantly, connects to node on first tool call

## Tools

### Read-only blockchain queries

| Tool | Purpose |
|------|---------|
| `kaspa_get_info` | Node health (sync status, mempool, version) |
| `kaspa_get_server_info` | Network ID, RPC version, DAA score |
| `kaspa_get_block_dag_info` | DAG state (tips, difficulty, block count) |
| `kaspa_get_block` | Fetch block by hash with optional transactions |
| `kaspa_get_balance` | Address balance in sompi and KAS |
| `kaspa_get_utxos` | UTXO set for up to 100 addresses |
| `kaspa_find_transaction_in_block` | Find and parse a tx in a specific block |
| `kaspa_search_blocks_for_transaction` | BFS search recent blocks for a tx by ID |
| `kaspa_verify_kpm_anchor` | Verify a KPM anchor payload on-chain |
| `kaspa_get_coin_supply` | Circulating and max supply |

### Wallet management

| Tool | Purpose |
|------|---------|
| `kaspa_generate_mnemonic` | Generate BIP39 mnemonic, auto-activate wallet |
| `kaspa_get_my_address` | Show active wallet address and network |
| `kaspa_save_wallet` | Encrypt mnemonic to `~/.kaspa-mcp/wallet.enc` |
| `kaspa_load_wallet` | Decrypt and activate wallet for session |
| `kaspa_estimate_fee` | Fee estimates from connected node |

### Transactions

| Tool | Purpose |
|------|---------|
| `kaspa_send_transaction` | Build, sign, submit KAS transfer (with optional payload) |

## Prerequisites

- Node.js 20+
- A running rusty-kaspa node with wRPC Borsh enabled

```bash
# Testnet-12
supertypo/rusty-kaspad --testnet --netsuffix=12 --utxoindex

# Mainnet
kaspad --utxoindex
```

## Install

```bash
git clone https://github.com/27inator/Kaspa-node-mcp.git
cd kaspa-node-mcp
npm install
npm run build
```

## Usage

### With Claude Code (stdio)

Add to your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "kaspa-node": {
      "command": "node",
      "args": ["/path/to/kaspa-node-mcp/dist/index.js"],
      "env": {
        "KASPA_ENDPOINT": "ws://localhost:17210"
      }
    }
  }
}
```

### With OpenClaw (HTTP)

```bash
KASPA_ENDPOINT=ws://localhost:17210 TRANSPORT=http PORT=3001 node dist/index.js
```

Then register in OpenClaw as an MCP endpoint at `http://localhost:3001/mcp`.

## Wallet Setup

### First time

```
1. Use kaspa_generate_mnemonic        → wallet auto-activates, shows address
2. Use kaspa_save_wallet(password)    → encrypted to ~/.kaspa-mcp/wallet.enc
3. Fund the address with testnet KAS
```

### Every session after

```
Server starts → "Encrypted wallet found. Use kaspa_load_wallet to unlock."

1. Use kaspa_load_wallet(password)    → wallet unlocked, ready to use
```

No environment variables needed. The mnemonic is encrypted at rest with AES-256-GCM (scrypt key derivation, N=65536, r=8, p=1). File permissions: `0600`.

### Alternative: environment variables

If you prefer env vars over the encrypted file:

```bash
KASPA_MNEMONIC="your 24 word mnemonic phrase here"
# or
KASPA_PRIVATE_KEY="hex_private_key"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KASPA_ENDPOINT` | `ws://localhost:17210` | wRPC Borsh WebSocket URL |
| `KASPA_NETWORK` | *(auto-detected)* | Network: mainnet, testnet-10, testnet-11, testnet-12 |
| `KASPA_MNEMONIC` | | BIP39 mnemonic phrase (optional if using encrypted wallet) |
| `KASPA_PRIVATE_KEY` | | Hex private key, alternative to mnemonic |
| `KASPA_ACCOUNT_INDEX` | `0` | BIP44 account index |
| `TRANSPORT` | `stdio` | Transport: `stdio` or `http` |
| `PORT` | `3000` | HTTP port (http transport only) |

## Default Ports by Network

| Network | wRPC Borsh | wRPC JSON |
|---------|-----------|-----------|
| Mainnet | 17110 | 18110 |
| Testnet-10 | 17210 | 18210 |
| Testnet-11 | 17310 | 18310 |
| Testnet-12 | 17210 | 18210 |

This server uses **wRPC Borsh** (17xxx ports), not JSON.

## KPM Anchor Verification

The `kaspa_verify_kpm_anchor` tool parses KPM's on-chain payload format:

```
Bytes: "KPM1" (4 bytes) || modeByte (1 byte) || hash (32 bytes)
Total: 37 bytes

modeByte 0x01 = INDIVIDUAL (single event hash)
modeByte 0x02 = MERKLE (Merkle root)
```

Verification flow:
1. KPM anchors data in block B with txid T
2. Call `kaspa_verify_kpm_anchor` with blockHash=B, transactionId=T, expectedHash=X
3. Tool fetches block, finds tx, parses KPM payload
4. Returns `verified: true` if on-chain hash matches

## Development

```bash
npm run dev    # Watch mode (tsc --watch)
npm run build  # Compile to dist/
npm start      # Run server
```

### Tests

```bash
node test-wallet-store.mjs   # Encrypted wallet: 34 assertions
node test-full-workflow.mjs  # End-to-end: generate → save → load
node test-smoke.mjs          # Node integration (requires running TN12 node)
```

## License

MIT
