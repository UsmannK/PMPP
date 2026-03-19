import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { streamSSE } from "hono/streaming";
import {
  createPublicClient,
  http,
  keccak256,
  toBytes,
  formatUnits,
  type Log,
  type Address,
} from "viem";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PORT = Number(process.env.PORT ?? process.env.OBSERVER_PORT ?? 3001);

// Tempo mainnet standard escrow
const STANDARD_ESCROW: Address = "0x33b901018174DDabE4841042ab76ba85D4e24f25";
const STANDARD_RPC = process.env.RPC_URL ?? "https://gracious-knuth:goofy-chandrasekhar@rpc.tempo.xyz";

// PrivacyEscrowZK — deployed on Tempo mainnet
const PRIVACY_ESCROW: Address = (process.env.ESCROW_CONTRACT as Address) ?? "0x472d53B0F5d3b8e5E6f03859961a0db63a97fA9d";
const PRIVACY_RPC = STANDARD_RPC;

const POLL_INTERVAL = Number(process.env.POLL_INTERVAL ?? 3000);

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

const standardClient = createPublicClient({
  transport: http(STANDARD_RPC),
});

const privacyClient = createPublicClient({ transport: http(PRIVACY_RPC) });

// ---------------------------------------------------------------------------
// Event signatures
// ---------------------------------------------------------------------------

// Standard escrow events (same shape, payee = merchant directly)
const STANDARD_SIGS: Record<string, string> = {
  ChannelOpened: keccak256(toBytes("ChannelOpened(bytes32,address,address,address,address,bytes32,uint256)")),
  Settled: keccak256(toBytes("Settled(bytes32,address,address,uint256,uint256,uint256)")),
  ChannelClosed: keccak256(toBytes("ChannelClosed(bytes32,address,address,uint256,uint256)")),
  TopUp: keccak256(toBytes("TopUp(bytes32,address,address,uint256,uint256)")),
  CloseRequested: keccak256(toBytes("CloseRequested(bytes32,address,address,uint256)")),
  ChannelExpired: keccak256(toBytes("ChannelExpired(bytes32,address,address)")),
};

// TIP-20 TransferWithMemo for one-time MPP charges
const TRANSFER_WITH_MEMO_SIG = keccak256(toBytes("TransferWithMemo(address,address,uint256,bytes32)"));

// MPP attribution tag: keccak256("mpp")[0..4] + version byte 0x01
const MPP_MEMO_PREFIX = "0xef1ed71201";

// pathUSD on Tempo mainnet
const PATH_USD: Address = (process.env.CURRENCY as Address) ?? "0x20C000000000000000000000b9537d11c60E8b50";

// PrivacyEscrowZK events (Poseidon-based, uint256 commitments)
const PRIVACY_SIGS: Record<string, string> = {
  ...STANDARD_SIGS,
  MerchantCommitmentSet: keccak256(toBytes("MerchantCommitmentSet(bytes32,bytes32)")),
  NoteCommitted: keccak256(toBytes("NoteCommitted(uint256,uint256,bytes32)")),
  NoteRedeemed: keccak256(toBytes("NoteRedeemed(uint256,address,address,uint256)")),
};

function invertSigs(sigs: Record<string, string>): Record<string, string> {
  const inv: Record<string, string> = {};
  for (const [name, sig] of Object.entries(sigs)) inv[sig] = name;
  return inv;
}

const STANDARD_SIG_TO_NAME = invertSigs(STANDARD_SIGS);
const PRIVACY_SIG_TO_NAME = invertSigs(PRIVACY_SIGS);

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

interface ObserverEvent {
  source: "standard" | "privacy";
  type: string;
  block: number;
  tx: string;
  txFull: string;
  fields: { key: string; value: string; raw?: string; exposed: boolean }[];
}

function addr(a: string): string {
  return `${a.slice(0, 6)}…${a.slice(-4)}`;
}

function amt(wei: bigint): string {
  return formatUnits(wei, 6);
}

// ---------------------------------------------------------------------------
// Standard escrow parser — everything is visible
// ---------------------------------------------------------------------------

function parseStandardLog(log: Log): ObserverEvent | null {
  const topic0 = log.topics[0];
  if (!topic0) return null;
  const eventName = STANDARD_SIG_TO_NAME[topic0];
  if (!eventName) return null;

  const block = Number(log.blockNumber ?? 0);
  const txFull = log.transactionHash ?? "0x";
  const tx = txFull.slice(0, 10) + "…";
  const topics = log.topics;
  const data = log.data ?? "0x";
  const channelId = topics[1] ?? "0x";

  switch (eventName) {
    case "ChannelOpened": {
      const payer = "0x" + (topics[2] ?? "").slice(26);
      const payee = "0x" + (topics[3] ?? "").slice(26);
      const deposit = BigInt("0x" + data.slice(194, 258));
      return {
        source: "standard", type: "ChannelOpened", block, tx, txFull,
        fields: [
          { key: "channelId", value: channelId.slice(0, 10) + "…", raw: channelId, exposed: true },
          { key: "payer", value: addr(payer), raw: payer, exposed: true },
          { key: "merchant (payee)", value: addr(payee), raw: payee, exposed: true },
          { key: "deposit", value: amt(deposit) + " pathUSD", exposed: true },
          { key: "payer→merchant link", value: `${addr(payer)} → ${addr(payee)}`, raw: `${payer} → ${payee}`, exposed: true },
        ],
      };
    }
    case "Settled": {
      const payer = "0x" + (topics[2] ?? "").slice(26);
      const payee = "0x" + (topics[3] ?? "").slice(26);
      const delta = BigInt("0x" + data.slice(66, 130));
      return {
        source: "standard", type: "Settled", block, tx, txFull,
        fields: [
          { key: "channelId", value: channelId.slice(0, 10) + "…", raw: channelId, exposed: true },
          { key: "payer", value: addr(payer), raw: payer, exposed: true },
          { key: "merchant (payee)", value: addr(payee), raw: payee, exposed: true },
          { key: "delta paid", value: amt(delta) + " USDC", exposed: true },
          { key: "funds sent to", value: addr(payee) + " (merchant directly)", raw: payee, exposed: true },
        ],
      };
    }
    case "ChannelClosed": {
      const payer = "0x" + (topics[2] ?? "").slice(26);
      const payee = "0x" + (topics[3] ?? "").slice(26);
      const settled = BigInt("0x" + data.slice(2, 66));
      const refunded = BigInt("0x" + data.slice(66, 130));
      return {
        source: "standard", type: "ChannelClosed", block, tx, txFull,
        fields: [
          { key: "channelId", value: channelId.slice(0, 10) + "…", raw: channelId, exposed: true },
          { key: "payer", value: addr(payer), raw: payer, exposed: true },
          { key: "merchant (payee)", value: addr(payee), raw: payee, exposed: true },
          { key: "total paid to merchant", value: amt(settled) + " USDC", exposed: true },
          { key: "refunded to payer", value: amt(refunded) + " USDC", exposed: true },
        ],
      };
    }
    case "TopUp": {
      const payer = "0x" + (topics[2] ?? "").slice(26);
      const payee = "0x" + (topics[3] ?? "").slice(26);
      const additional = BigInt("0x" + data.slice(2, 66));
      return {
        source: "standard", type: "TopUp", block, tx, txFull,
        fields: [
          { key: "channelId", value: channelId.slice(0, 10) + "…", raw: channelId, exposed: true },
          { key: "payer", value: addr(payer), raw: payer, exposed: true },
          { key: "merchant (payee)", value: addr(payee), raw: payee, exposed: true },
          { key: "added", value: amt(additional) + " USDC", exposed: true },
        ],
      };
    }
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// MPP one-time charge parser — TransferWithMemo on pathUSD
// ---------------------------------------------------------------------------

function parseMppChargeLog(log: Log): ObserverEvent | null {
  const topic0 = log.topics[0];
  if (!topic0 || topic0 !== TRANSFER_WITH_MEMO_SIG) return null;

  const topics = log.topics;
  const data = log.data ?? "0x";

  // memo is topic[3] (indexed bytes32)
  const memo = topics[3] ?? "";
  // Check MPP attribution prefix: tag (4 bytes) + version (1 byte)
  if (!memo.toLowerCase().startsWith(MPP_MEMO_PREFIX)) return null;

  const from = "0x" + (topics[1] ?? "").slice(26);
  const to = "0x" + (topics[2] ?? "").slice(26);
  const amount = BigInt("0x" + data.slice(2, 66));

  const block = Number(log.blockNumber ?? 0);
  const txFull = log.transactionHash ?? "0x";
  const tx = txFull.slice(0, 10) + "…";

  // Decode server + client fingerprints from memo
  const serverFp = "0x" + memo.slice(12, 32);
  const clientFp = memo.slice(32, 52);
  const isAnonymous = clientFp === "00000000000000000000";

  return {
    source: "standard", type: "MppCharge", block, tx, txFull,
    fields: [
      { key: "payer", value: addr(from), raw: from, exposed: true },
      { key: "merchant (recipient)", value: addr(to), raw: to, exposed: true },
      { key: "amount", value: amt(amount) + " pathUSD", exposed: true },
      { key: "memo", value: memo.slice(0, 14) + "…", raw: memo, exposed: true },
      { key: "server fingerprint", value: serverFp.slice(0, 10) + "…", raw: serverFp, exposed: true },
      { key: "client fingerprint", value: isAnonymous ? "(anonymous)" : "0x" + clientFp.slice(0, 8) + "…", raw: isAnonymous ? "" : "0x" + clientFp, exposed: true },
      { key: "payer→merchant link", value: `${addr(from)} → ${addr(to)}`, raw: `${from} → ${to}`, exposed: true },
    ],
  };
}

// ---------------------------------------------------------------------------
// Privacy escrow parser — merchant identity hidden
// ---------------------------------------------------------------------------

function parsePrivacyLog(log: Log): ObserverEvent | null {
  const topic0 = log.topics[0];
  if (!topic0) return null;
  const eventName = PRIVACY_SIG_TO_NAME[topic0];
  if (!eventName) return null;

  const block = Number(log.blockNumber ?? 0);
  const txFull = log.transactionHash ?? "0x";
  const tx = txFull.slice(0, 10) + "…";
  const topics = log.topics;
  const data = log.data ?? "0x";
  const channelId = topics[1] ?? "0x";

  switch (eventName) {
    case "ChannelOpened": {
      const payer = "0x" + (topics[2] ?? "").slice(26);
      const payee = "0x" + (topics[3] ?? "").slice(26);
      const deposit = BigInt("0x" + data.slice(194, 258));
      return {
        source: "privacy", type: "ChannelOpened", block, tx, txFull,
        fields: [
          { key: "channelId", value: channelId.slice(0, 10) + "…", raw: channelId, exposed: true },
          { key: "payer", value: addr(payer), raw: payer, exposed: true },
          { key: "payee (contract)", value: addr(payee), raw: payee, exposed: true },
          { key: "deposit", value: amt(deposit) + " pathUSD", exposed: true },
          { key: "merchant identity", value: "???", exposed: false },
          { key: "payer→merchant link", value: "???", exposed: false },
        ],
      };
    }
    case "MerchantCommitmentSet": {
      const commitment = "0x" + data.slice(2, 66);
      return {
        source: "privacy", type: "MerchantCommitmentSet", block, tx, txFull,
        fields: [
          { key: "channel", value: channelId.slice(0, 10) + "…", raw: channelId, exposed: true },
          { key: "commitment hash", value: commitment.slice(0, 14) + "…", raw: commitment, exposed: true },
          { key: "merchant public key", value: "???", exposed: false },
          { key: "who this merchant is", value: "???", exposed: false },
        ],
      };
    }
    case "Settled": {
      const payer = "0x" + (topics[2] ?? "").slice(26);
      const delta = BigInt("0x" + data.slice(66, 130));
      return {
        source: "privacy", type: "Settled", block, tx, txFull,
        fields: [
          { key: "channelId", value: channelId.slice(0, 10) + "…", raw: channelId, exposed: true },
          { key: "payer", value: addr(payer), raw: payer, exposed: true },
          { key: "delta", value: amt(delta) + " USDC", exposed: true },
          { key: "funds sent to", value: "escrow (note minted)", exposed: true },
          { key: "which merchant earned this", value: "???", exposed: false },
        ],
      };
    }
    case "NoteCommitted": {
      const noteIndex = Number(BigInt(topics[1] ?? "0x0"));
      const noteCommitment = topics[2] ?? "0x";
      return {
        source: "privacy", type: "NoteCommitted", block, tx, txFull,
        fields: [
          { key: "note index", value: String(noteIndex), exposed: true },
          { key: "commitment", value: noteCommitment.slice(0, 14) + "…", raw: noteCommitment, exposed: true },
          { key: "note amount", value: "???", exposed: false },
          { key: "who can redeem", value: "???", exposed: false },
        ],
      };
    }
    case "NoteRedeemed": {
      const nullifier = topics[1] ?? "0x";
      const recipient = "0x" + (topics[2] ?? "").slice(26);
      const redeemAmt = BigInt("0x" + data.slice(66, 130));
      return {
        source: "privacy", type: "NoteRedeemed", block, tx, txFull,
        fields: [
          { key: "nullifier", value: nullifier.slice(0, 14) + "…", raw: nullifier, exposed: true },
          { key: "recipient", value: addr(recipient), raw: recipient, exposed: true },
          { key: "amount", value: amt(redeemAmt) + " pathUSD", exposed: true },
          { key: "ZK proof", value: "✓ verified on-chain", exposed: true },
          { key: "which merchant", value: "??? (hidden by ZK proof)", exposed: false },
          { key: "which session/payer", value: "??? (hidden by ZK proof)", exposed: false },
          { key: "channelId", value: "??? (not in calldata)", exposed: false },
        ],
      };
    }
    case "ChannelClosed": {
      const payer = "0x" + (topics[2] ?? "").slice(26);
      const settled = BigInt("0x" + data.slice(2, 66));
      const refunded = BigInt("0x" + data.slice(66, 130));
      return {
        source: "privacy", type: "ChannelClosed", block, tx, txFull,
        fields: [
          { key: "channelId", value: channelId.slice(0, 10) + "…", raw: channelId, exposed: true },
          { key: "payer", value: addr(payer), raw: payer, exposed: true },
          { key: "settled (in notes)", value: amt(settled) + " USDC", exposed: true },
          { key: "refunded", value: amt(refunded) + " USDC", exposed: true },
          { key: "merchant payout address", value: "???", exposed: false },
        ],
      };
    }
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// Pollers
// ---------------------------------------------------------------------------

// (polling is per-SSE-connection, see /events handler)

// Max block range per getLogs request (RPCs often limit to ~10k)
const MAX_RANGE = 50000n;

// Standard escrow first activity is around block 10,100,000
const STANDARD_FROM_BLOCK = BigInt(process.env.STANDARD_FROM_BLOCK ?? "9726354");

// PrivacyEscrowZK deployed around block 10,243,900
const PRIVACY_FROM_BLOCK = BigInt(process.env.PRIVACY_FROM_BLOCK ?? "10243900");

const CONCURRENCY = 16;

async function streamLogsInChunks(
  client: typeof standardClient,
  address: Address,
  fromBlock: bigint,
  toBlock: bigint,
  onLogs: (logs: Log[]) => Promise<void>,
  topics?: (`0x${string}` | null)[],
): Promise<void> {
  // Build list of chunk ranges
  const chunks: { from: bigint; to: bigint; idx: number }[] = [];
  let cursor = fromBlock;
  let idx = 0;
  while (cursor <= toBlock) {
    const end = cursor + MAX_RANGE > toBlock ? toBlock : cursor + MAX_RANGE;
    chunks.push({ from: cursor, to: end, idx: idx++ });
    cursor = end + 1n;
  }

  // Process chunks in order as they complete, with up to CONCURRENCY in flight
  let nextToEmit = 0;
  const completed = new Map<number, Log[]>();

  const tryFlush = async () => {
    while (completed.has(nextToEmit)) {
      const logs = completed.get(nextToEmit)!;
      completed.delete(nextToEmit);
      if (logs.length > 0) await onLogs(logs);
      nextToEmit++;
    }
  };

  for (let i = 0; i < chunks.length; i += CONCURRENCY) {
    const batch = chunks.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map(async (chunk) => {
        try {
          const params: any = { address, fromBlock: chunk.from, toBlock: chunk.to };
          if (topics) params.topics = topics;
          return { idx: chunk.idx, logs: await client.getLogs(params) };
        } catch {
          return { idx: chunk.idx, logs: [] as Log[] };
        }
      })
    );
    for (const r of batchResults) completed.set(r.idx, r.logs);
    await tryFlush();
  }
}

async function fetchLogsInChunks(
  client: typeof standardClient,
  address: Address,
  fromBlock: bigint,
  toBlock: bigint,
  topics?: (`0x${string}` | null)[],
): Promise<Log[]> {
  const allLogs: Log[] = [];
  await streamLogsInChunks(client, address, fromBlock, toBlock, async (logs) => {
    allLogs.push(...logs);
  }, topics);
  return allLogs;
}

const CHARGE_TOPICS: `0x${string}`[] = [TRANSFER_WITH_MEMO_SIG as `0x${string}`];

// ---------------------------------------------------------------------------
// Server-side event cache
// ---------------------------------------------------------------------------

const eventCache: ObserverEvent[] = [];
let cacheSyncedBlock = 0n;
let cacheReady = false;
let cachePromise: Promise<void> | null = null;

async function buildCache(): Promise<void> {
  console.log("[cache] Building initial event cache…");
  const current = await standardClient.getBlockNumber();

  // MPP one-time charges
  await streamLogsInChunks(standardClient, PATH_USD, STANDARD_FROM_BLOCK, current, async (logs) => {
    for (const log of logs) {
      const event = parseMppChargeLog(log);
      if (event) eventCache.push(event);
    }
  }, CHARGE_TOPICS);

  // Standard escrow sessions
  await streamLogsInChunks(standardClient, STANDARD_ESCROW, STANDARD_FROM_BLOCK, current, async (logs) => {
    for (const log of logs) {
      const event = parseStandardLog(log);
      if (event) eventCache.push(event);
    }
  });

  // Privacy escrow (on Tempo mainnet)
  try {
    const privCurrent = await privacyClient.getBlockNumber();
    await streamLogsInChunks(privacyClient, PRIVACY_ESCROW, PRIVACY_FROM_BLOCK, privCurrent, async (logs) => {
      for (const log of logs) {
        const event = parsePrivacyLog(log);
        if (event) eventCache.push(event);
      }
    });
  } catch (e) {
    console.log("[cache] Privacy escrow fetch error:", e);
  }

  cacheSyncedBlock = current;
  cacheReady = true;
  console.log(`[cache] Ready — ${eventCache.length} events cached up to block ${current}`);
}

async function pollNewEvents(): Promise<ObserverEvent[]> {
  const newEvents: ObserverEvent[] = [];
  try {
    const head = await standardClient.getBlockNumber();
    if (head <= cacheSyncedBlock) return newEvents;
    const from = cacheSyncedBlock + 1n;

    const [chargeLogs, escrowLogs, privacyLogs] = await Promise.all([
      fetchLogsInChunks(standardClient, PATH_USD, from, head, CHARGE_TOPICS),
      fetchLogsInChunks(standardClient, STANDARD_ESCROW, from, head),
      fetchLogsInChunks(privacyClient, PRIVACY_ESCROW, from, head),
    ]);
    for (const log of chargeLogs) {
      const event = parseMppChargeLog(log);
      if (event) newEvents.push(event);
    }
    for (const log of escrowLogs) {
      const event = parseStandardLog(log);
      if (event) newEvents.push(event);
    }
    for (const log of privacyLogs) {
      const event = parsePrivacyLog(log);
      if (event) newEvents.push(event);
    }

    if (newEvents.length > 0) eventCache.push(...newEvents);
    cacheSyncedBlock = head;
  } catch {}
  return newEvents;
}

// Start cache build immediately; live polling starts once ready
cachePromise = buildCache().then(() => {
  setInterval(pollNewEvents, POLL_INTERVAL);
});

// ---------------------------------------------------------------------------
// Hono server
// ---------------------------------------------------------------------------

const app = new Hono();

app.get("/", (c) => c.html(HTML));

app.get("/api/events", async (c) => {
  if (!cacheReady) await cachePromise;
  return c.json({ count: eventCache.length, syncedBlock: String(cacheSyncedBlock), events: eventCache });
});

app.get("/events", (c) => {
  return streamSSE(c, async (stream) => {
    // Wait for cache to be ready (only blocks the first connection if still loading)
    if (!cacheReady) await cachePromise;

    // Replay cached events instantly
    const snapshot = eventCache.slice();
    for (const event of snapshot) {
      await stream.writeSSE({ event: "escrow", data: JSON.stringify(event) });
    }
    await stream.writeSSE({ event: "sync-done", data: "" });

    // Track what this connection has already seen
    let cursor = eventCache.length;

    try {
      while (true) {
        // Send any new events that arrived since last check
        const current = eventCache.length;
        if (current > cursor) {
          const newEvents = eventCache.slice(cursor, current);
          for (const event of newEvents) {
            await stream.writeSSE({ event: "escrow", data: JSON.stringify(event) });
          }
          cursor = current;
        }

        await stream.writeSSE({ event: "ping", data: "" });
        await stream.sleep(POLL_INTERVAL);
      }
    } catch {}
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const privacyLine = PRIVACY_ESCROW
  ? `║  Privacy:  ${PRIVACY_ESCROW.slice(0, 42).padEnd(42)} ║`
  : `║  Privacy:  ${"(not configured)".padEnd(42)} ║`;

console.log(`
╔══════════════════════════════════════════════════════════╗
║     🔍  ESCROW OBSERVER — SIDE BY SIDE COMPARISON  🔍   ║
╠══════════════════════════════════════════════════════════╣
║  Standard: ${STANDARD_ESCROW.slice(0, 42).padEnd(42)} ║
║     Chain: Tempo mainnet (4217)                          ║
${privacyLine}
╚══════════════════════════════════════════════════════════╝
`);

serve({ fetch: app.fetch, port: PORT }, (info) => {
  console.log(`Observer UI: http://localhost:${info.port}`);
});

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔍 Escrow Observer — Standard vs Privacy</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'SF Mono', 'Fira Code', monospace;
    background: #0a0a0f;
    color: #c8c8d0;
    min-height: 100vh;
    overflow: hidden;
  }
  header {
    background: linear-gradient(135deg, #12121a, #1a1a2e);
    border-bottom: 1px solid #2a2a3e;
    padding: 14px 24px;
    text-align: center;
  }
  header h1 { font-size: 16px; color: #e0e0e8; }
  header p { font-size: 11px; color: #555; margin-top: 4px; }

  .columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    height: calc(100vh - 170px);
  }
  .column { position: relative; display: flex; flex-direction: column; }
  .column.standard { border-right: 1px solid #2a2a3e; }
  .column .graph-area { flex: 1; position: relative; min-height: 0; }
  .column svg { width: 100%; height: 100%; }

  .event-log {
    height: 180px;
    overflow-y: auto;
    border-top: 1px solid #2a2a3e;
    background: #0d0d14;
    font-size: 10px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    padding: 4px 0;
  }
  .event-log .log-entry {
    padding: 2px 12px;
    display: flex;
    gap: 8px;
    border-bottom: 1px solid #1a1a2e;
  }
  .event-log .log-entry:hover { background: #1a1a2e; }
  .log-block { color: #555; min-width: 70px; }
  .log-type { color: #fbbf24; min-width: 80px; }
  .log-detail { color: #c8c8d0; }
  .log-exposed { color: #f87171; }
  .log-hidden { color: #4ade80; font-style: italic; }
  .log-type-priv { color: #4ade80; }

  .col-label {
    position: absolute;
    top: 12px;
    left: 16px;
    z-index: 10;
    pointer-events: none;
  }
  .col-label h2 {
    font-size: 13px;
    font-weight: bold;
    color: #e0e0e8;
  }
  .col-label .badge {
    display: inline-block;
    font-size: 9px;
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 4px;
  }
  .standard .badge { background: #3a1525; color: #f87171; }
  .privacy .badge { background: #1a3a2a; color: #4ade80; }
  .col-label .subtitle { font-size: 10px; color: #444; margin-top: 2px; }
  .col-label .stats { font-size: 11px; color: #666; margin-top: 6px; }
  .col-label .stats span { color: #00d4aa; font-weight: bold; }

  .stats-bar {
    position: fixed;
    bottom: 36px;
    left: 0;
    right: 0;
    background: #12121aee;
    border-top: 1px solid #2a2a3e;
    display: grid;
    grid-template-columns: 1fr 1fr;
    padding: 10px 24px;
    z-index: 100;
    backdrop-filter: blur(8px);
  }
  .stats-section h3 {
    font-size: 11px;
    color: #888;
    margin-bottom: 6px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .stats-row {
    display: flex;
    gap: 16px;
  }
  .stat-box {
    background: #1a1a2e;
    border: 1px solid #2a2a3e;
    border-radius: 6px;
    padding: 6px 14px;
    min-width: 120px;
  }
  .stat-box.highlight-red { border-color: #f87171; }
  .stat-box.highlight-green { border-color: #4ade80; }
  .stat-label { font-size: 9px; color: #666; text-transform: uppercase; }
  .stat-value { font-size: 18px; font-weight: bold; color: #e0e0e8; }
  .stat-sub { font-size: 10px; color: #555; }
  .stat-box.highlight-red .stat-value { color: #f87171; }
  .stat-box.highlight-green .stat-value { color: #4ade80; }

  .legend {
    position: fixed;
    bottom: 12px;
    left: 50%;
    transform: translateX(-50%);
    background: #12121aee;
    border: 1px solid #2a2a3e;
    border-radius: 6px;
    padding: 8px 20px;
    display: flex;
    gap: 20px;
    font-size: 10px;
    z-index: 100;
  }
  .legend-item { display: flex; align-items: center; gap: 6px; }
  .legend-dot { width: 10px; height: 10px; border-radius: 50%; }
</style>
</head>
<body>

<header>
  <h1>🔍 Escrow Observer — Payment Graph: Standard vs PrivacyEscrowZK</h1>
  <p>Left: full payer→merchant graph visible · Right: merchant identity hidden</p>
</header>

<div class="columns">
  <div class="column standard">
    <div class="col-label">
      <h2>TempoStreamChannel</h2>
      <div class="badge">🚨 Full Graph Exposed</div>
      <div class="subtitle">Tempo Mainnet · 0x33b9…4f25</div>
      <div class="stats">
        Payers: <span id="std-payers">0</span> ·
        Merchants: <span id="std-merchants">0</span> ·
        Charges: <span id="std-charges">0</span> ·
        Total: $<span id="std-volume">0</span>
      </div>
    </div>
    <div class="graph-area">
      <svg id="svg-standard"></svg>
    </div>
    <div class="event-log" id="std-log"></div>
  </div>

  <div class="column privacy">
    <div class="col-label">
      <h2>PrivacyEscrowZK</h2>
      <div class="badge">🔒 ZK-Proven Merchant Privacy</div>
      <div class="subtitle">Tempo Mainnet · ${PRIVACY_ESCROW.slice(0, 10)}…</div>
      <div class="stats">
        Payers: <span id="priv-payers">0</span> ·
        Notes: <span id="priv-notes">0</span> ·
        Redeemed: <span id="priv-redeemed">0</span>
      </div>
    </div>
    <div class="graph-area">
      <svg id="svg-privacy"></svg>
    </div>
    <div class="event-log" id="priv-log"></div>
  </div>
</div>
<div class="stats-bar">
  <div class="stats-section">
    <h3>Standard MPP (all on-chain, fully visible)</h3>
    <div class="stats-row">
      <div class="stat-box">
        <div class="stat-label">Sessions (channels)</div>
        <div class="stat-value" id="stat-sessions">0</div>
        <div class="stat-sub">$<span id="stat-session-vol">0.00</span></div>
      </div>
      <div class="stat-box">
        <div class="stat-label">One-time charges</div>
        <div class="stat-value" id="stat-charges">0</div>
        <div class="stat-sub">$<span id="stat-charge-vol">0.00</span></div>
      </div>
      <div class="stat-box highlight-red">
        <div class="stat-label">Total exposed</div>
        <div class="stat-value">$<span id="stat-total-vol">0.00</span></div>
        <div class="stat-sub"><span id="stat-total-txns">0</span> transactions</div>
      </div>
    </div>
  </div>
  <div class="stats-section">
    <h3>PrivacyEscrowZK (ZK-proven privacy)</h3>
    <div class="stats-row">
      <div class="stat-box">
        <div class="stat-label">Notes minted</div>
        <div class="stat-value" id="stat-priv-notes">0</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">Notes redeemed</div>
        <div class="stat-value" id="stat-priv-redeemed">0</div>
      </div>
      <div class="stat-box highlight-green">
        <div class="stat-label">Merchant links exposed</div>
        <div class="stat-value">0</div>
        <div class="stat-sub">unlinkable by design</div>
      </div>
    </div>
  </div>
</div>

<div class="legend">
  <div class="legend-item"><div class="legend-dot" style="background:#60a5fa"></div> Payer</div>
  <div class="legend-item"><div class="legend-dot" style="background:#fbbf24"></div> Escrow</div>
  <div class="legend-item"><div class="legend-dot" style="background:#4ade80"></div> Merchant (visible)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#f87171"></div> Hidden / Unknown</div>
  <div class="legend-item" style="margin-left:auto;color:#555">Charges: block <span id="sync-charges">…</span> · Sessions: block <span id="sync-sessions">…</span></div>
</div>

<script>
// =========================================================================
// Graph state
// =========================================================================

function fmtAmt(v) {
  if (v >= 1) return '$' + v.toFixed(2);
  if (v >= 0.01) return '$' + v.toFixed(4);
  if (v === 0) return '$0';
  return '$' + v.toPrecision(3);
}

class PaymentGraph {
  constructor(svgId, isPrivacy) {
    this.isPrivacy = isPrivacy;
    this.nodes = new Map();    // id → { id, type, label, amount }
    this.edges = new Map();    // "src→tgt" → { source, target, amount, label }
    this.svg = d3.select('#' + svgId);
    this.width = this.svg.node().parentElement.clientWidth;
    this.height = this.svg.node().parentElement.clientHeight;

    // Escrow node always exists
    const escrowId = isPrivacy ? 'priv-escrow' : 'std-escrow';
    this.nodes.set(escrowId, {
      id: escrowId,
      type: 'escrow',
      label: isPrivacy ? 'PrivacyEscrowZK' : 'Escrow',
      amount: 0
    });

    const w = this.width;
    const h = this.height;
    this.simulation = d3.forceSimulation()
      .force('charge', d3.forceManyBody().strength(-80))
      .force('x', d3.forceX().x(d => {
        if (d.type === 'payer') return w * 0.12;
        if (d.type === 'escrow') return w * 0.5;
        return w * 0.85; // merchant, hidden, redeemer
      }).strength(1.0))
      .force('y', d3.forceY().y(d => {
        // If node has a row assignment, use it for clean lanes
        if (d.row != null) {
          const totalRows = d.totalRows || 1;
          const margin = 40;
          const usable = h - margin * 2;
          return margin + (d.row + 0.5) * (usable / totalRows);
        }
        return h / 2;
      }).strength(d => d.row != null ? 0.8 : 0.03))
      .force('collision', d3.forceCollide().radius(d => d.type === 'hidden' ? 30 : 18))
      .force('link', d3.forceLink().id(d => d.id).distance(120))
      .on('tick', () => this.tick());

    // Arrow marker
    this.svg.append('defs').append('marker')
      .attr('id', svgId + '-arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 28)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#444');

    this.linkGroup = this.svg.append('g');
    this.labelGroup = this.svg.append('g');
    this.nodeGroup = this.svg.append('g');

    this.arrowId = svgId + '-arrow';
    this.update();
  }

  addPayer(id, label) {
    if (!this.nodes.has(id)) {
      this.nodes.set(id, { id, type: 'payer', label, amount: 0 });
    }
  }

  addMerchant(id, label) {
    if (!this.nodes.has(id)) {
      const type = this.isPrivacy ? 'hidden' : 'merchant';
      this.nodes.set(id, { id, type, label, amount: 0 });
    }
  }

  addRedeemer(id, label) {
    if (!this.nodes.has(id)) {
      this.nodes.set(id, { id, type: 'redeemer', label, amount: 0 });
    }
  }

  addEdge(sourceId, targetId, amount) {
    const key = sourceId + '→' + targetId;
    const existing = this.edges.get(key);
    if (existing) {
      existing.amount += amount;
      existing.label = fmtAmt(existing.amount);
    } else {
      this.edges.set(key, {
        source: sourceId,
        target: targetId,
        amount,
        label: fmtAmt(amount)
      });
    }
  }

  update() {
    const nodes = Array.from(this.nodes.values());
    const edges = Array.from(this.edges.values());

    // Links
    const links = this.linkGroup.selectAll('line').data(edges, d => d.source.id ? d.source.id + '→' + d.target.id : d.source + '→' + d.target);
    links.exit().remove();
    links.enter().append('line')
      .attr('stroke', '#333')
      .attr('stroke-width', d => Math.max(1, Math.min(6, d.amount / 2)))
      .attr('marker-end', 'url(#' + this.arrowId + ')');

    // Edge labels
    const labels = this.labelGroup.selectAll('text').data(edges, d => d.source.id ? d.source.id + '→' + d.target.id : d.source + '→' + d.target);
    labels.exit().remove();
    labels.enter().append('text')
      .attr('font-size', 10)
      .attr('font-family', 'SF Mono, monospace')
      .attr('fill', '#888')
      .attr('text-anchor', 'middle');

    // Update existing labels
    this.labelGroup.selectAll('text').text(d => d.label);

    // Update link widths
    this.linkGroup.selectAll('line')
      .attr('stroke-width', d => Math.max(1, Math.min(6, d.amount / 2)));

    // Nodes
    const nodeColors = { payer: '#60a5fa', escrow: '#fbbf24', merchant: '#4ade80', hidden: '#f87171', redeemer: '#fbbf24' };
    const nodeJoin = this.nodeGroup.selectAll('g.node').data(nodes, d => d.id);
    nodeJoin.exit().remove();
    const enter = nodeJoin.enter().append('g').attr('class', 'node');

    enter.append('circle')
      .attr('r', d => d.type === 'escrow' ? 24 : 18)
      .attr('fill', d => nodeColors[d.type] || '#666')
      .attr('stroke', d => d.type === 'hidden' ? '#f87171' : '#333')
      .attr('stroke-width', d => d.type === 'hidden' ? 2 : 1)
      .attr('opacity', d => d.type === 'hidden' ? 0.5 : 0.9)
      .attr('stroke-dasharray', d => d.type === 'hidden' ? '4,3' : 'none');

    enter.append('text')
      .attr('dy', d => d.type === 'escrow' ? 36 : 30)
      .attr('text-anchor', 'middle')
      .attr('font-size', 10)
      .attr('font-family', 'SF Mono, monospace')
      .attr('fill', d => d.type === 'hidden' ? '#f87171' : '#aaa')
      .text(d => d.label);

    // Icon text inside circle
    enter.append('text')
      .attr('dy', 4)
      .attr('text-anchor', 'middle')
      .attr('font-size', d => d.type === 'escrow' ? 12 : 10)
      .attr('fill', '#000')
      .attr('font-weight', 'bold')
      .text(d => {
        if (d.type === 'escrow') return '🏦';
        if (d.type === 'payer') return '👤';
        if (d.type === 'merchant') return '🏪';
        if (d.type === 'hidden') return '❓';
        if (d.type === 'redeemer') return '💰';
        return '';
      });

    this.simulation.nodes(nodes);
    this.simulation.force('link').links(edges);
    this.simulation.alpha(0.3).restart();
  }

  tick() {
    this.linkGroup.selectAll('line')
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    this.labelGroup.selectAll('text')
      .attr('x', d => (d.source.x + d.target.x) / 2)
      .attr('y', d => (d.source.y + d.target.y) / 2 - 6);

    this.nodeGroup.selectAll('g.node')
      .attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
  }
}

// =========================================================================
// Initialize graphs
// =========================================================================

const stdGraph = new PaymentGraph('svg-standard', false);
const privGraph = new PaymentGraph('svg-privacy', true);

let stdPayers = new Set(), stdMerchants = new Set(), stdVolume = 0, stdCharges = 0;
let stdSessions = 0, stdSessionVol = 0, stdChargeVol = 0;
let privPayers = new Set(), privNotes = 0, privRedeemed = 0;

function updateStdStats() {
  document.getElementById('std-volume').textContent = stdVolume.toFixed(2);
  document.getElementById('std-payers').textContent = stdPayers.size;
  document.getElementById('std-merchants').textContent = stdMerchants.size;
  document.getElementById('std-charges').textContent = stdCharges;
  document.getElementById('stat-sessions').textContent = stdSessions;
  document.getElementById('stat-session-vol').textContent = stdSessionVol.toFixed(2);
  document.getElementById('stat-charges').textContent = stdCharges;
  document.getElementById('stat-charge-vol').textContent = stdChargeVol.toFixed(2);
  document.getElementById('stat-total-vol').textContent = stdVolume.toFixed(2);
  document.getElementById('stat-total-txns').textContent = stdSessions + stdCharges;
}

let syncChargeBlock = 0;
let syncSessionBlock = 0;
const stdLogEl = document.getElementById('std-log');
const MAX_LOG_ENTRIES = 500;

function appendLog(event) {
  const entry = document.createElement('div');
  entry.className = 'log-entry';

  let detail = '';
  if (event.type === 'MppCharge') {
    const payer = event.fields.find(f => f.key === 'payer')?.value || '?';
    const merchant = event.fields.find(f => f.key === 'merchant (recipient)')?.value || '?';
    const amt = event.fields.find(f => f.key === 'amount')?.value || '?';
    detail = '<span class="log-exposed">' + payer + ' → ' + merchant + '</span> ' + amt;
  } else if (event.type === 'ChannelOpened') {
    const payer = event.fields.find(f => f.key === 'payer')?.value || '?';
    const merchant = event.fields.find(f => f.key === 'merchant (payee)')?.value || '?';
    const dep = event.fields.find(f => f.key === 'deposit')?.value || '?';
    detail = '<span class="log-exposed">' + payer + ' → ' + merchant + '</span> deposit ' + dep;
  } else if (event.type === 'ChannelClosed') {
    const payer = event.fields.find(f => f.key === 'payer')?.value || '?';
    const merchant = event.fields.find(f => f.key === 'merchant (payee)')?.value || '?';
    const settled = event.fields.find(f => f.key === 'total paid to merchant')?.value || '?';
    detail = '<span class="log-exposed">' + payer + ' → ' + merchant + '</span> settled ' + settled;
  } else {
    detail = event.fields.map(f => f.value).join(' ');
  }

  entry.innerHTML = '<span class="log-block">' + event.block.toLocaleString() + '</span>'
    + '<span class="log-type">' + event.type + '</span>'
    + '<span class="log-detail">' + detail + '</span>';

  stdLogEl.appendChild(entry);
  if (stdLogEl.children.length > MAX_LOG_ENTRIES) stdLogEl.removeChild(stdLogEl.firstChild);
  stdLogEl.scrollTop = stdLogEl.scrollHeight;
}

const privLogEl = document.getElementById('priv-log');

function appendPrivLog(event) {
  const entry = document.createElement('div');
  entry.className = 'log-entry';

  let detail = '';
  if (event.type === 'ChannelOpened') {
    const payer = event.fields.find(f => f.key === 'payer')?.value || '?';
    const dep = event.fields.find(f => f.key === 'deposit')?.value || '?';
    detail = '<span class="log-exposed">' + payer + '</span> → <span class="log-hidden">escrow</span> deposit ' + dep;
  } else if (event.type === 'MerchantCommitmentSet') {
    const ch = event.fields.find(f => f.key === 'channel')?.value || '?';
    detail = 'commitment set on ' + ch + ' <span class="log-hidden">(merchant ???)</span>';
  } else if (event.type === 'Settled') {
    const payer = event.fields.find(f => f.key === 'payer')?.value || '?';
    const delta = event.fields.find(f => f.key === 'delta')?.value || '?';
    detail = '<span class="log-exposed">' + payer + '</span> settled ' + delta + ' <span class="log-hidden">→ note (merchant ???)</span>';
  } else if (event.type === 'NoteCommitted') {
    const idx = event.fields.find(f => f.key === 'note index')?.value || '?';
    const comm = event.fields.find(f => f.key === 'commitment')?.value || '?';
    detail = 'note #' + idx + ' committed ' + comm + ' <span class="log-hidden">(who? ???)</span>';
  } else if (event.type === 'NoteRedeemed') {
    const recipient = event.fields.find(f => f.key === 'recipient')?.value || '?';
    const amt = event.fields.find(f => f.key === 'amount')?.value || '?';
    detail = '<span class="log-exposed">' + recipient + '</span> redeemed ' + amt + ' <span class="log-hidden">(from which payer? ???)</span>';
  } else if (event.type === 'ChannelClosed') {
    const payer = event.fields.find(f => f.key === 'payer')?.value || '?';
    const settled = event.fields.find(f => f.key === 'settled (in notes)')?.value || '?';
    detail = '<span class="log-exposed">' + payer + '</span> closed, settled=' + settled + ' <span class="log-hidden">(merchant ???)</span>';
  } else {
    detail = event.fields.map(f => f.exposed ? f.value : '<span class="log-hidden">???</span>').join(' ');
  }

  entry.innerHTML = '<span class="log-block">' + event.block.toLocaleString() + '</span>'
    + '<span class="log-type log-type-priv">' + event.type + '</span>'
    + '<span class="log-detail">' + detail + '</span>';

  privLogEl.appendChild(entry);
  if (privLogEl.children.length > MAX_LOG_ENTRIES) privLogEl.removeChild(privLogEl.firstChild);
  privLogEl.scrollTop = privLogEl.scrollHeight;
}

// =========================================================================
// Top-50 graph filter
// =========================================================================

const TOP_MERCHANTS = 10;
const PAYERS_PER_MERCHANT = 5;
let synced = false;

// merchant → total closed volume
const merchantVolume = new Map();
// merchant → Map(payer → volume)
const merchantPayers = new Map();

function rebuildStdGraph() {
  stdGraph.nodes = new Map();
  stdGraph.edges = new Map();

  // Collect all payer→merchant paths as independent rows
  const rows = [];
  const topMerchants = Array.from(merchantVolume.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, TOP_MERCHANTS);

  for (const [merchant, totalVol] of topMerchants) {
    const payers = merchantPayers.get(merchant);
    if (payers) {
      const topPayers = Array.from(payers.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, PAYERS_PER_MERCHANT);
      for (const [payer, vol] of topPayers) {
        rows.push({ payer, merchant, vol });
      }
    }
  }

  const totalRows = rows.length || 1;
  for (let r = 0; r < rows.length; r++) {
    const { payer, merchant, vol } = rows[r];
    // Each row gets its own payer, escrow, and merchant node
    const payerId = 'std-p-' + r;
    const escrowId = 'std-esc-' + r;
    const merchantId = 'std-m-' + r;
    stdGraph.nodes.set(payerId, { id: payerId, type: 'payer', label: payer, amount: vol, row: r, totalRows });
    stdGraph.nodes.set(escrowId, { id: escrowId, type: 'escrow', label: 'Escrow', amount: vol, row: r, totalRows });
    stdGraph.nodes.set(merchantId, { id: merchantId, type: 'merchant', label: merchant, amount: vol, row: r, totalRows });
    stdGraph.addEdge(payerId, escrowId, vol);
    stdGraph.addEdge(escrowId, merchantId, vol);
  }

  stdGraph.update();
}

function updateSyncBlocks(event) {
  if (event.type === 'MppCharge') {
    if (event.block > syncChargeBlock) {
      syncChargeBlock = event.block;
      document.getElementById('sync-charges').textContent = syncChargeBlock.toLocaleString();
    }
  } else {
    if (event.block > syncSessionBlock) {
      syncSessionBlock = event.block;
      document.getElementById('sync-sessions').textContent = syncSessionBlock.toLocaleString();
    }
  }
}

function updateStdStatsFromEvent(event) {
  if (event.type === 'ChannelOpened') {
    stdSessions++;
  }
  if (event.type === 'ChannelClosed') {
    const settledStr = event.fields.find(f => f.key === 'total paid to merchant')?.value || '0';
    const settled = parseFloat(settledStr) || 0;
    if (settled > 0) { stdSessionVol += settled; stdVolume += settled; }
  }
  if (event.type === 'MppCharge') {
    const amtStr = event.fields.find(f => f.key === 'amount')?.value || '0';
    const chargeAmt = parseFloat(amtStr) || 0;
    const payer = event.fields.find(f => f.key === 'payer')?.value || '?';
    const merchant = event.fields.find(f => f.key === 'merchant (recipient)')?.value || '?';
    stdPayers.add(payer);
    stdMerchants.add(merchant);
    stdCharges++;
    stdChargeVol += chargeAmt;
    stdVolume += chargeAmt;
  }
}

function trackForGraph(event) {
  if (event.type !== 'ChannelClosed') return;
  const payer = event.fields.find(f => f.key === 'payer')?.value || '?';
  const merchant = event.fields.find(f => f.key === 'merchant (payee)')?.value || '?';
  const s = event.fields.find(f => f.key === 'total paid to merchant')?.value || '0';
  const vol = parseFloat(s) || 0;
  if (vol <= 0) return;

  stdPayers.add(payer);
  stdMerchants.add(merchant);
  merchantVolume.set(merchant, (merchantVolume.get(merchant) || 0) + vol);
  if (!merchantPayers.has(merchant)) merchantPayers.set(merchant, new Map());
  const mp = merchantPayers.get(merchant);
  mp.set(payer, (mp.get(payer) || 0) + vol);
}

function handleEvent(event) {
  if (event.source === 'standard') {
    updateSyncBlocks(event);
    appendLog(event);
    updateStdStatsFromEvent(event);
    trackForGraph(event);
    updateStdStats();

    if (synced && event.type === 'ChannelClosed') {
      rebuildStdGraph();
    }
  }

  if (event.source === 'privacy') {
    const escrowId = 'priv-escrow';
    appendPrivLog(event);

    if (event.type === 'ChannelOpened') {
      const payer = event.fields.find(f => f.key === 'payer')?.value || '?';
      const deposit = event.fields.find(f => f.key === 'deposit')?.value || '0';
      const payerId = 'priv-p-' + payer;

      privPayers.add(payer);
      privGraph.addPayer(payerId, payer);
      privGraph.addEdge(payerId, escrowId, parseFloat(deposit) || 0);
      privGraph.update();

      document.getElementById('priv-payers').textContent = privPayers.size;
    }

    if (event.type === 'Settled') {
      const deltaStr = event.fields.find(f => f.key === 'delta')?.value || '0';
      const payer = event.fields.find(f => f.key === 'payer')?.value || '?';
      const payerId = 'priv-p-' + payer;

      privPayers.add(payer);
      privGraph.addPayer(payerId, payer);
      privGraph.addEdge(payerId, escrowId, parseFloat(deltaStr) || 0);
      privGraph.update();
    }

    if (event.type === 'NoteCommitted') {
      privNotes++;
      document.getElementById('priv-notes').textContent = privNotes;
      document.getElementById('stat-priv-notes').textContent = privNotes;

      // Show note as a hidden node — no link to any merchant
      const idx = event.fields.find(f => f.key === 'note index')?.value || '?';
      const noteId = 'priv-note-' + idx;
      privGraph.nodes.set(noteId, { id: noteId, type: 'hidden', label: 'Note #' + idx + ' ???', amount: 0 });
      privGraph.addEdge(escrowId, noteId, 0);
      privGraph.update();
    }

    if (event.type === 'NoteRedeemed') {
      privRedeemed++;
      document.getElementById('priv-redeemed').textContent = privRedeemed;
      document.getElementById('stat-priv-redeemed').textContent = privRedeemed;
    }
  }
}

function handleSyncDone() {
  synced = true;
  rebuildStdGraph();
}

// =========================================================================
// SSE
// =========================================================================

const es = new EventSource('/events');
es.addEventListener('escrow', (e) => {
  try { handleEvent(JSON.parse(e.data)); } catch(err) { console.error(err); }
});
es.addEventListener('sync-done', () => handleSyncDone());
</script>

</body>
</html>`;

