/**
 * Type definitions for Kaspa wRPC JSON responses.
 *
 * These match the actual response format from rusty-kaspa v1.1.0+.
 * Field names are camelCase as returned by the node.
 */

// ── getInfo / getServerInfo ──────────────────────────────────────────

export interface GetInfoResponse {
  hasMessageId: boolean;
  hasNotifyCommand: boolean;
  isSynced: boolean;
  isUtxoIndexed: boolean;
  mempoolSize: number;
  p2pId: string;
  serverVersion: string;
}

export interface GetServerInfoResponse {
  hasUtxoIndex: boolean;
  isSynced: boolean;
  networkId: string;
  rpcApiRevision: number;
  rpcApiVersion: number;
  serverVersion: string;
  virtualDaaScore: number;
}

// ── getBlockDagInfo ──────────────────────────────────────────────────

export interface GetBlockDagInfoResponse {
  blockCount: number;
  difficulty: number;
  headerCount: number;
  network: string;
  pastMedianTime: number;
  pruningPointHash: string;
  sink: string;
  tipHashes: string[];
  virtualDaaScore: number;
  virtualParentHashes: string[];
}

// ── getBlock ─────────────────────────────────────────────────────────

export interface BlockHeader {
  acceptedIdMerkleRoot: string;
  bits: number;
  blueScore: number;
  blueWork: string;
  daaScore: number;
  hash: string;
  hashMerkleRoot: string;
  nonce: number;
  parentsByLevel: string[][];
  pruningPoint: string;
  timestamp: number;
  utxoCommitment: string;
  version: number;
}

export interface TransactionInput {
  previousOutpoint: {
    index: number;
    transactionId: string;
  };
  sequence: number;
  sigOpCount: number;
  signatureScript: string;
  verboseData: unknown;
}

export interface ScriptPublicKey {
  scriptPublicKey: string;
  value: number;
  verboseData?: {
    scriptPublicKeyAddress: string;
    scriptPublicKeyType: string;
  };
}

export interface Transaction {
  gas: number;
  inputs: TransactionInput[];
  lockTime: number;
  mass: number;
  outputs: ScriptPublicKey[];
  payload: string;
  subnetworkId: string;
  verboseData?: {
    blockHash: string;
    blockTime: number;
    computeMass: number;
    hash: string;
    transactionId: string;
  };
  version: number;
}

export interface BlockVerboseData {
  blueScore: number;
  childrenHashes: string[];
  difficulty: number;
  hash: string;
  isChainBlock: boolean;
  isHeaderOnly: boolean;
  mergeSetBluesHashes: string[];
  mergeSetRedsHashes: string[];
  selectedParentHash: string;
  transactionIds: string[];
}

export interface Block {
  header: BlockHeader;
  transactions: Transaction[];
  verboseData: BlockVerboseData;
}

export interface GetBlockResponse {
  block: Block;
}

// ── getUtxosByAddresses ──────────────────────────────────────────────

export interface UtxoEntry {
  address: string;
  outpoint: {
    index: number;
    transactionId: string;
  };
  utxoEntry: {
    amount: number;
    blockDaaScore: number;
    isCoinbase: boolean;
    scriptPublicKey: string;
  };
}

export interface GetUtxosByAddressesResponse {
  entries: UtxoEntry[];
}

// ── getBalanceByAddress ──────────────────────────────────────────────

export interface GetBalanceByAddressResponse {
  balance: number;
}

// ── getMempoolEntries ────────────────────────────────────────────────

export interface MempoolEntry {
  fee: number;
  is_orphan: boolean;
  transaction: Transaction;
}

export interface GetMempoolEntriesResponse {
  mempoolEntries: MempoolEntry[];
}

// ── getVirtualChainFromBlock ─────────────────────────────────────────

export interface AcceptedTransactionIds {
  acceptingBlockHash: string;
  acceptedTransactionIds: string[];
}

export interface GetVirtualChainFromBlockResponse {
  addedChainBlockHashes: string[];
  removedChainBlockHashes: string[];
  acceptedTransactionIds?: AcceptedTransactionIds[];
}

// ── getCoinSupply ────────────────────────────────────────────────────

export interface GetCoinSupplyResponse {
  circulatingSompi: number;
  maxSompi: number;
}

// ── submitTransaction ────────────────────────────────────────────────

export interface SubmitTransactionResponse {
  transactionId: string;
}

// ── KPM-specific payload parsing ─────────────────────────────────────

export interface KpmAnchorPayload {
  /** Raw hex payload */
  raw: string;
  /** true if payload starts with KPM1 magic bytes (4b504d31) */
  isKpmPayload: boolean;
  /** "INDIVIDUAL" (0x01) or "MERKLE" (0x02) */
  anchorMode?: string;
  /** 32-byte hash (hex) — event hash or merkle root */
  hash?: string;
}

// ── Sompi/KAS conversion ─────────────────────────────────────────────

/** 1 KAS = 100,000,000 sompi */
export const SOMPI_PER_KAS = 100_000_000;

export function sompiToKas(sompi: number): string {
  return (sompi / SOMPI_PER_KAS).toFixed(8);
}
