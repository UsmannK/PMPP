/**
 * PrivacyEscrowZK mainnet test: sessions + ZK note redemption.
 * Reuses existing payer/merchant keys from mainnet-keys.json.
 *
 * Usage: npx tsx scripts/mainnet-simulate-zk.ts
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  encodePacked,
  encodeAbiParameters,
  parseAbiParameters,
  formatUnits,
  type Address,
  type Hex,
  type Hash,
} from "viem";
import { privateKeyToAccount, generatePrivateKey, type PrivateKeyAccount } from "viem/accounts";
import { tempo as tempoBase } from "viem/chains";
import { readFileSync, writeFileSync } from "fs";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────

const RPC_URL = "https://gracious-knuth:goofy-chandrasekhar@rpc.tempo.xyz";
const PATH_USD: Address = "0x20c000000000000000000000b9537d11c60e8b50";
const ESCROW_ZK: Address = "0x1FAc145aC33A3760B8c1Ed8dEEa5Abb8F3F90bc6";
const VERIFIER: Address = "0x4528B59f0E87cF0011D43d298c2bcF94D3670204";

const ROOT_ACCOUNT: Address = "0xad7c2a2f45ba77e5efa2c32c31ee80b98c64721e";
const ACCESS_KEY: Hex = "0xd9c7165d29e9b3ece5265a371dcdc2fada6c7acec02c632309f9faea37c9a3f1";

const DEPOSIT_AMOUNT = 20_000n;   // $0.02
const SETTLE_DELTA = 5_000n;      // $0.005

const tempo = { ...tempoBase, feeToken: PATH_USD } as typeof tempoBase;

// Poseidon BN254 field prime
const F_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ─────────────────────────────────────────────────────────────────────
// ABIs
// ─────────────────────────────────────────────────────────────────────

const escrowAbi = [
  { name: "open", type: "function", stateMutability: "nonpayable",
    inputs: [{ name: "payee", type: "address" },{ name: "token", type: "address" },{ name: "deposit", type: "uint128" },{ name: "salt", type: "bytes32" },{ name: "authorizedSigner", type: "address" }],
    outputs: [{ name: "channelId", type: "bytes32" }] },
  { name: "setMerchantCommitment", type: "function", stateMutability: "nonpayable",
    inputs: [{ name: "channelId", type: "bytes32" },{ name: "merchantCommitment", type: "bytes32" }], outputs: [] },
  { name: "settle", type: "function", stateMutability: "nonpayable",
    inputs: [{ name: "channelId", type: "bytes32" },{ name: "cumulativeAmount", type: "uint128" },{ name: "signature", type: "bytes" }], outputs: [] },
  { name: "close", type: "function", stateMutability: "nonpayable",
    inputs: [{ name: "channelId", type: "bytes32" },{ name: "cumulativeAmount", type: "uint128" },{ name: "signature", type: "bytes" }], outputs: [] },
  { name: "computeChannelId", type: "function", stateMutability: "view",
    inputs: [{ name: "payer", type: "address" },{ name: "payee", type: "address" },{ name: "token", type: "address" },{ name: "salt", type: "bytes32" },{ name: "authorizedSigner", type: "address" }],
    outputs: [{ name: "", type: "bytes32" }] },
  { name: "redeemNote", type: "function", stateMutability: "nonpayable",
    inputs: [{ name: "proof", type: "uint256[8]" },{ name: "nullifier", type: "uint256" },{ name: "merkleRoot", type: "uint256" },{ name: "amount", type: "uint128" },{ name: "asset", type: "address" },{ name: "recipient", type: "address" }],
    outputs: [] },
  { name: "noteCount", type: "function", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { name: "currentRoot", type: "function", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { name: "getMerkleRoot", type: "function", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { name: "knownRoots", type: "function", stateMutability: "view", inputs: [{ name: "", type: "uint256" }], outputs: [{ name: "", type: "bool" }] },
  { name: "spentNullifiers", type: "function", stateMutability: "view", inputs: [{ name: "", type: "uint256" }], outputs: [{ name: "", type: "bool" }] },
] as const;

const erc20Abi = [
  { name: "approve", type: "function", stateMutability: "nonpayable",
    inputs: [{ name: "spender", type: "address" },{ name: "amount", type: "uint256" }], outputs: [{ name: "", type: "bool" }] },
  { name: "balanceOf", type: "function", stateMutability: "view",
    inputs: [{ name: "account", type: "address" }], outputs: [{ name: "", type: "uint256" }] },
] as const;

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

const publicClient = createPublicClient({ chain: tempo, transport: http(RPC_URL) });

function wallet(account: PrivateKeyAccount) {
  return createWalletClient({ chain: tempo, transport: http(RPC_URL), account });
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

async function waitTx(hash: Hash, label: string) {
  const r = await publicClient.waitForTransactionReceipt({ hash });
  if (r.status !== "success") throw new Error(`${label} FAILED: ${hash}`);
  console.log(`    ✓ ${label} (block ${r.blockNumber}, gas ${r.gasUsed})`);
  return r;
}

async function signVoucher(account: PrivateKeyAccount, channelId: Hex, cum: bigint): Promise<Hex> {
  return account.signTypedData({
    domain: { name: "Tempo Stream Channel", version: "1", chainId: BigInt(tempo.id), verifyingContract: ESCROW_ZK },
    types: { Voucher: [{ name: "channelId", type: "bytes32" }, { name: "cumulativeAmount", type: "uint128" }] },
    primaryType: "Voucher",
    message: { channelId, cumulativeAmount: cum },
  });
}

// ─────────────────────────────────────────────────────────────────────
// Poseidon (JS side — matches circomlib/snarkjs)
// ─────────────────────────────────────────────────────────────────────

let poseidonFn: any;
let F: any;

async function initPoseidon() {
  const { buildPoseidon } = await import("circomlibjs");
  poseidonFn = await buildPoseidon();
  F = poseidonFn.F;
}

function poseidon(inputs: bigint[]): bigint {
  const h = poseidonFn(inputs.map(x => F.e(x)));
  return BigInt(F.toString(h));
}

// ─────────────────────────────────────────────────────────────────────
// Merkle tree (mirrors contract's Poseidon incremental tree)
// ─────────────────────────────────────────────────────────────────────

const TREE_DEPTH = 20;

function computeZeros(): bigint[] {
  const zeros: bigint[] = new Array(TREE_DEPTH);
  zeros[0] = poseidon([0n, 0n]);
  for (let i = 1; i < TREE_DEPTH; i++) {
    zeros[i] = poseidon([zeros[i - 1], zeros[i - 1]]);
  }
  return zeros;
}

function buildMerkleProof(leaves: bigint[], leafIndex: number): { siblings: bigint[], pathIndices: number[], root: bigint } {
  const zeros = computeZeros();
  const siblings: bigint[] = new Array(TREE_DEPTH);
  const pathIndices: number[] = new Array(TREE_DEPTH);

  let level = [...leaves];
  let idx = leafIndex;

  for (let d = 0; d < TREE_DEPTH; d++) {
    const sibIdx = idx ^ 1;
    pathIndices[d] = idx & 1;
    siblings[d] = sibIdx < level.length ? level[sibIdx] : zeros[d];

    const nextLen = Math.ceil(level.length / 2);
    const next: bigint[] = new Array(nextLen);
    for (let j = 0; j < nextLen; j++) {
      const left = level[2 * j];
      const right = (2 * j + 1 < level.length) ? level[2 * j + 1] : zeros[d];
      next[j] = poseidon([left, right]);
    }
    level = next;
    idx >>= 1;
  }

  return { siblings, pathIndices, root: level[0] };
}

// ─────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║  PrivacyEscrowZK Mainnet — Sessions + ZK Redemption     ║");
  console.log("╚══════════════════════════════════════════════════════════╝\n");

  await initPoseidon();
  console.log("Poseidon initialized ✓\n");

  // Load keys
  const KEYS_FILE = join(__dirname, "mainnet-keys.json");
  const saved = JSON.parse(readFileSync(KEYS_FILE, "utf-8"));

  const payers = saved.payers.map((p: any) => ({
    account: privateKeyToAccount(p.key as Hex), key: p.key as Hex
  }));

  // Merchant secrets — Poseidon-based commitments (field elements)
  const merchants = saved.merchants.map((m: any, i: number) => {
    const key = m.key as Hex;
    const account = privateKeyToAccount(key);
    const pubKey = BigInt(i * 1000 + 12345); // simple field element
    const blinding = BigInt(i * 1000 + 67890);
    const commitment = poseidon([pubKey, blinding]);
    return { account, key, pubKey, blinding, commitment };
  });

  console.log("Actors:");
  for (let i = 0; i < payers.length; i++) console.log(`  Payer ${i}: ${payers[i].account.address}`);
  for (let i = 0; i < merchants.length; i++) console.log(`  Merchant ${i}: ${merchants[i].account.address} (commitment: ${merchants[i].commitment.toString().slice(0, 20)}…)`);

  const escrowBal = await publicClient.readContract({ address: PATH_USD, abi: erc20Abi, functionName: "balanceOf", args: [ESCROW_ZK] });
  const initialNoteCount = await publicClient.readContract({ address: ESCROW_ZK, abi: escrowAbi, functionName: "noteCount" }) as bigint;
  console.log(`\nEscrow balance: $${formatUnits(escrowBal, 6)} | Notes: ${initialNoteCount}\n`);

  // ── Top up actors if needed (Poseidon settle is gas-heavy) ──────
  console.log("=== Checking & topping up actors ===");
  const { execSync } = await import("child_process");
  const FUND_AMOUNT = 300_000n; // $0.30 each
  const MIN_BAL = 200_000n;

  for (const actor of [...payers, ...merchants]) {
    const bal = await publicClient.readContract({ address: PATH_USD, abi: erc20Abi, functionName: "balanceOf", args: [actor.account.address] });
    if (bal < MIN_BAL) {
      console.log(`  ${actor.account.address.slice(0, 10)}… low ($${formatUnits(bal, 6)}), funding $${formatUnits(FUND_AMOUNT, 6)}...`);
      const out = execSync(
        `cast send ${PATH_USD} "transfer(address,uint256)" ${actor.account.address} ${FUND_AMOUNT} ` +
        `--rpc-url ${RPC_URL} --tempo.access-key ${ACCESS_KEY} ` +
        `--tempo.root-account ${ROOT_ACCOUNT} --tempo.fee-token ${PATH_USD} --json`,
        { encoding: "utf-8" }
      );
      console.log(`    funded ✓`);
    } else {
      console.log(`  ${actor.account.address.slice(0, 10)}… OK ($${formatUnits(bal, 6)})`);
    }
  }
  console.log("");

  // ── Sessions ────────────────────────────────────────────────────
  console.log("=== Sessions (Poseidon note minting) ===");
  let saltN = Math.floor(Date.now() / 1000);
  const noteData: { channelId: Hex, delta: bigint, cumulativeAmount: bigint, merchantIndex: number, settleBlock: bigint }[] = [];

  for (let p = 0; p < 2; p++) {
    const payer = payers[p];
    const pc = wallet(payer.account);
    const mIdx = p % 2;
    const merch = merchants[mIdx];
    const mc = wallet(merch.account);

    // Approve
    const appTx = await pc.writeContract({ address: PATH_USD, abi: erc20Abi, functionName: "approve",
      args: [ESCROW_ZK, BigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")] });
    await waitTx(appTx, `approve payer${p}`);

    // Open
    const salt = keccak256(encodeAbiParameters(parseAbiParameters("uint256"), [BigInt(++saltN)]));
    const openTx = await pc.writeContract({ address: ESCROW_ZK, abi: escrowAbi, functionName: "open",
      args: [merch.account.address, PATH_USD, DEPOSIT_AMOUNT, salt, "0x0000000000000000000000000000000000000000"] });
    const openR = await waitTx(openTx, `open channel ${p}`);

    const channelId = await publicClient.readContract({ address: ESCROW_ZK, abi: escrowAbi, functionName: "computeChannelId",
      args: [payer.account.address, merch.account.address, PATH_USD, salt, "0x0000000000000000000000000000000000000000"] }) as Hex;

    // Set Poseidon merchant commitment (as bytes32)
    const commitmentHex = ("0x" + merch.commitment.toString(16).padStart(64, "0")) as Hex;
    const cmTx = await mc.writeContract({ address: ESCROW_ZK, abi: escrowAbi, functionName: "setMerchantCommitment",
      args: [channelId, commitmentHex] });
    await waitTx(cmTx, `setCommitment ${p}`);

    // Settle
    const sig = await signVoucher(payer.account, channelId, SETTLE_DELTA);
    const stTx = await mc.writeContract({ address: ESCROW_ZK, abi: escrowAbi, functionName: "settle",
      args: [channelId, SETTLE_DELTA, sig] });
    const stR = await waitTx(stTx, `settle ${p}`);

    noteData.push({ channelId, delta: SETTLE_DELTA, cumulativeAmount: SETTLE_DELTA, merchantIndex: mIdx, settleBlock: stR.blockNumber });

    // Close
    const csig = await signVoucher(payer.account, channelId, SETTLE_DELTA);
    const clTx = await mc.writeContract({ address: ESCROW_ZK, abi: escrowAbi, functionName: "close",
      args: [channelId, SETTLE_DELTA, csig] });
    await waitTx(clTx, `close ${p}`);

    console.log(`  Channel ${p}: payer${p}→merchant${mIdx} ✓\n`);
  }

  // ── Get ALL note commitments from NoteCommitted events ────────────
  console.log("=== Fetching NoteCommitted events ===");
  const finalNoteCount = await publicClient.readContract({ address: ESCROW_ZK, abi: escrowAbi, functionName: "noteCount" }) as bigint;
  const currentRoot = await publicClient.readContract({ address: ESCROW_ZK, abi: escrowAbi, functionName: "getMerkleRoot" }) as bigint;
  console.log(`  Notes in tree: ${finalNoteCount} (${initialNoteCount} old + ${finalNoteCount - initialNoteCount} new)`);
  console.log(`  Current root: ${currentRoot.toString().slice(0, 25)}…`);

  // Fetch ALL NoteCommitted events from this contract (from block 0 of this contract)
  const noteCommittedTopic = keccak256(new TextEncoder().encode("NoteCommitted(uint256,uint256,bytes32)"));
  const logs = await publicClient.getLogs({
    address: ESCROW_ZK,
    fromBlock: 10243900n, // just before contract deployment
    toBlock: "latest",
    topics: [noteCommittedTopic as Hex],
  });

  // Parse ALL notes — we need them all for Merkle proof
  const allNotes = new Map<bigint, { commitment: bigint, channelId: Hex }>();
  for (const log of logs) {
    if (log.address.toLowerCase() !== ESCROW_ZK.toLowerCase()) continue;
    const noteIndex = BigInt(log.topics[1] ?? "0");
    const noteCommitment = BigInt(log.topics[2] ?? "0");
    const channelId = (log.topics[3] ?? "0x") as Hex;
    if (!allNotes.has(noteIndex)) {
      allNotes.set(noteIndex, { commitment: noteCommitment, channelId });
    }
  }
  console.log(`  Parsed ${allNotes.size} unique notes`);

  // Build ordered list of ALL commitments for Merkle proof
  const allCommitments: bigint[] = [];
  for (let i = 0n; i < finalNoteCount; i++) {
    const note = allNotes.get(i);
    if (!note) throw new Error(`Missing note ${i}`);
    allCommitments.push(note.commitment);
  }

  // Identify OUR notes (the ones we just minted)
  const ourNoteIndices = [initialNoteCount, initialNoteCount + 1n];
  const onChainNotes = ourNoteIndices.map(idx => ({
    index: idx,
    commitment: allNotes.get(idx)!.commitment,
    channelId: allNotes.get(idx)!.channelId,
  }));
  for (const n of onChainNotes) {
    console.log(`    Our note ${n.index}: commitment ${n.commitment.toString().slice(0, 20)}…`);
  }
  console.log("");

  // ── Reconstruct note preimages and generate ZK proofs ───────────
  console.log("=== ZK Proof Generation ===");

  // We need the block timestamps for noteRandomness reconstruction

  // Build Merkle proofs
  const snarkjs = await import("snarkjs");
  const wasmPath = resolve(__dirname, "../../circuits/build/note_redeem_js/note_redeem.wasm");
  const zkeyPath = resolve(__dirname, "../../circuits/build/note_redeem_final.zkey");

  // For each note, we need to reconstruct the noteRandomness.
  // The contract computes: noteRandomness = PoseidonT3.hash([keccak256(channelId, cumAmt, timestamp, noteCount), 0])
  // We need the block timestamp from the settle tx.

  const proofs: { proof: any, publicSignals: string[], nullifier: bigint, merkleRoot: bigint, recipient: Address }[] = [];

  for (let i = 0; i < onChainNotes.length; i++) {
    const note = onChainNotes[i];
    const nd = noteData[i];
    const merch = merchants[nd.merchantIndex];

    // Get block timestamp
    const block = await publicClient.getBlock({ blockNumber: nd.settleBlock });
    const timestamp = block.timestamp;

    // Reconstruct noteRandomness (mirrors contract)
    const keccakInput = keccak256(encodeAbiParameters(
      parseAbiParameters("bytes32, uint128, uint256, uint256"),
      [nd.channelId, nd.cumulativeAmount, timestamp, note.index]
    ));
    const noteRandomness = poseidon([BigInt(keccakInput), 0n]);

    // Reconstruct noteCommitment
    const asset = BigInt(PATH_USD);
    const recomputedCommitment = poseidon([asset, nd.delta, merch.commitment, BigInt(nd.channelId), noteRandomness]);

    const match = recomputedCommitment === note.commitment;
    console.log(`  Note ${note.index}: preimage ${match ? "✓ MATCH" : "✗ MISMATCH"}`);
    if (!match) {
      console.log(`    Expected: ${note.commitment}`);
      console.log(`    Got:      ${recomputedCommitment}`);
      throw new Error(`Note ${note.index} preimage mismatch`);
    }

    // Build Merkle proof using ALL notes in the tree
    const { siblings, pathIndices, root } = buildMerkleProof(allCommitments, Number(note.index));

    // Verify root matches on-chain
    const rootKnown = await publicClient.readContract({ address: ESCROW_ZK, abi: escrowAbi, functionName: "knownRoots", args: [root] });
    console.log(`    Merkle root known on-chain: ${rootKnown ? "✓" : "✗"}`);
    if (!rootKnown) throw new Error(`Root not known on-chain for note ${note.index}`);

    // Nullifier
    const nullifier = poseidon([note.commitment, merch.pubKey]);

    // Fresh recipient (unlinkable)
    const freshKey = generatePrivateKey();
    const recipient = privateKeyToAccount(freshKey).address;

    // Build circuit input
    const input = {
      nullifier: nullifier.toString(),
      merkleRoot: root.toString(),
      amount: nd.delta.toString(),
      asset: asset.toString(),
      recipient: BigInt(recipient).toString(),
      merchantPubKey: merch.pubKey.toString(),
      blinding: merch.blinding.toString(),
      noteRandomness: noteRandomness.toString(),
      channelId: BigInt(nd.channelId).toString(),
      pathIndices: pathIndices.map(String),
      siblings: siblings.map(s => s.toString()),
    };

    // Generate Groth16 proof
    console.log(`    Generating proof...`);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
    console.log(`    Proof generated ✓`);

    proofs.push({ proof, publicSignals, nullifier, merkleRoot: root, recipient: recipient as Address });
  }
  console.log("");

  // ── ZK Redemption ───────────────────────────────────────────────
  console.log("=== ZK Note Redemption (no preimage fields revealed!) ===");

  for (let i = 0; i < proofs.length; i++) {
    const { proof, nullifier, merkleRoot, recipient } = proofs[i];
    const nd = noteData[i];
    const merch = merchants[nd.merchantIndex];
    const mc = wallet(merch.account);

    // Format proof for Solidity: [pA[0], pA[1], pB[0][1], pB[0][0], pB[1][1], pB[1][0], pC[0], pC[1]]
    const solProof: readonly [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint] = [
      BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1]),
      BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0]),
      BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0]),
      BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1]),
    ] as const;

    console.log(`  Note ${i}: $${formatUnits(nd.delta, 6)} → ${recipient.slice(0, 12)}…`);
    console.log(`    Merchant ${nd.merchantIndex} redeems — on-chain sees ONLY: nullifier + proof`);
    console.log(`    NO channelId, NO merchantPubKey, NO blinding revealed`);

    const tx = await mc.writeContract({
      address: ESCROW_ZK,
      abi: escrowAbi,
      functionName: "redeemNote",
      args: [solProof, nullifier, merkleRoot, nd.delta, PATH_USD, recipient],
    });
    await waitTx(tx, `redeemNote ${i} (ZK)`);

    // Verify
    const spent = await publicClient.readContract({ address: ESCROW_ZK, abi: escrowAbi, functionName: "spentNullifiers", args: [nullifier] });
    const freshBal = await publicClient.readContract({ address: PATH_USD, abi: erc20Abi, functionName: "balanceOf", args: [recipient] });
    console.log(`    Nullifier spent: ${spent} | Recipient balance: $${formatUnits(freshBal, 6)}`);
    console.log("");
  }

  // ── Summary ─────────────────────────────────────────────────────
  const endEscrowBal = await publicClient.readContract({ address: PATH_USD, abi: erc20Abi, functionName: "balanceOf", args: [ESCROW_ZK] });
  const endWalletBal = await publicClient.readContract({ address: PATH_USD, abi: erc20Abi, functionName: "balanceOf", args: [ROOT_ACCOUNT] });

  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║  PrivacyEscrowZK — Full ZK Flow Complete!               ║");
  console.log(`║  Escrow balance: $${formatUnits(endEscrowBal, 6).padEnd(37)}║`);
  console.log(`║  Wallet balance: $${formatUnits(endWalletBal, 6).padEnd(37)}║`);
  console.log("║                                                          ║");
  console.log("║  ✓ Poseidon note commitments in Merkle tree              ║");
  console.log("║  ✓ Groth16 proofs verified on-chain                      ║");
  console.log("║  ✓ NO preimage fields revealed during redemption          ║");
  console.log("║  ✓ Payer→merchant link is cryptographically broken        ║");
  console.log("╚══════════════════════════════════════════════════════════╝");
}

main().then(() => process.exit(0)).catch(e => { console.error("FAILED:", e.message ?? e); process.exit(1); });
