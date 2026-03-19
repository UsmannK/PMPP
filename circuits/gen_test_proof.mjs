/**
 * Generate a test proof for the ZK note redemption circuit.
 * Produces Solidity-ready proof data and public signals.
 *
 * Usage: node gen_test_proof.mjs
 */

import { buildPoseidon } from "circomlibjs";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const TREE_DEPTH = 20;

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  // ─── Test values (matching what the Solidity test will use) ───
  const asset = 1000n; // mock token address as uint256
  const amount = 2000000n; // 2e6 = $2
  const merchantPubKey = F.e("12345678901234567890");
  const blinding = F.e("98765432109876543210");
  const channelId = F.e("11111111111111111111");
  const noteRandomness = F.e("99999999999999999999");
  const recipient = 42069n; // mock recipient address

  // 1. merchantCommitment = Poseidon(merchantPubKey, blinding)
  const merchantCommitment = poseidon([merchantPubKey, blinding]);

  // 2. noteCommitment = Poseidon(asset, amount, merchantCommitment, channelId, noteRandomness)
  const noteCommitment = poseidon([asset, amount, merchantCommitment, channelId, noteRandomness]);

  // 3. nullifier = Poseidon(noteCommitment, merchantPubKey)
  const nullifier = poseidon([noteCommitment, merchantPubKey]);

  console.log("merchantCommitment:", F.toString(merchantCommitment));
  console.log("noteCommitment:", F.toString(noteCommitment));
  console.log("nullifier:", F.toString(nullifier));

  // 4. Build Merkle tree with this single leaf at index 0
  // Compute zero hashes
  const zeros = new Array(TREE_DEPTH);
  zeros[0] = poseidon([0n, 0n]);
  for (let i = 1; i < TREE_DEPTH; i++) {
    zeros[i] = poseidon([zeros[i - 1], zeros[i - 1]]);
  }

  // Insert leaf at index 0 (mirrors contract's _insertLeaf)
  let node = noteCommitment;
  const siblings = new Array(TREE_DEPTH);
  const pathIndices = new Array(TREE_DEPTH);

  for (let i = 0; i < TREE_DEPTH; i++) {
    // Index 0: always left child at every level
    pathIndices[i] = 0;
    siblings[i] = zeros[i];
    node = poseidon([node, zeros[i]]);
  }

  const merkleRoot = node;
  console.log("merkleRoot:", F.toString(merkleRoot));

  // 5. Build circuit input
  const input = {
    // Public
    nullifier: F.toString(nullifier),
    merkleRoot: F.toString(merkleRoot),
    amount: amount.toString(),
    asset: asset.toString(),
    recipient: recipient.toString(),
    // Private
    merchantPubKey: F.toString(merchantPubKey),
    blinding: F.toString(blinding),
    noteRandomness: F.toString(noteRandomness),
    channelId: F.toString(channelId),
    pathIndices: pathIndices.map(String),
    siblings: siblings.map(s => F.toString(s)),
  };

  // Write input
  const inputPath = resolve(__dirname, "build/input.json");
  const { writeFileSync } = await import("fs");
  writeFileSync(inputPath, JSON.stringify(input, null, 2));
  console.log("\nWrote input.json");

  // 6. Generate witness + proof using snarkjs
  const snarkjs = await import("snarkjs");
  const wasmPath = resolve(__dirname, "build/note_redeem_js/note_redeem.wasm");
  const zkeyPath = resolve(__dirname, "build/note_redeem_final.zkey");

  console.log("Generating proof...");
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );

  console.log("\nPublic signals:");
  console.log("  [0] nullifier:", publicSignals[0]);
  console.log("  [1] merkleRoot:", publicSignals[1]);
  console.log("  [2] amount:", publicSignals[2]);
  console.log("  [3] asset:", publicSignals[3]);
  console.log("  [4] recipient:", publicSignals[4]);

  // 7. Format proof for Solidity
  // Groth16Verifier expects: pA[2], pB[2][2], pC[2]
  // snarkjs outputs: proof.pi_a[3], proof.pi_b[3][2], proof.pi_c[3]
  const solProof = [
    proof.pi_a[0], proof.pi_a[1],
    proof.pi_b[0][1], proof.pi_b[0][0], // Note: B is transposed
    proof.pi_b[1][1], proof.pi_b[1][0],
    proof.pi_c[0], proof.pi_c[1],
  ];

  console.log("\n// ═══ Solidity test constants ═══");
  console.log(`uint256 constant MERCHANT_PUB_KEY = ${F.toString(merchantPubKey)};`);
  console.log(`uint256 constant BLINDING = ${F.toString(blinding)};`);
  console.log(`uint256 constant CHANNEL_ID = ${F.toString(channelId)};`);
  console.log(`uint256 constant NOTE_RANDOMNESS = ${F.toString(noteRandomness)};`);
  console.log(`uint256 constant MOCK_ASSET = ${asset};`);
  console.log(`uint128 constant NOTE_AMOUNT = ${amount};`);
  console.log(`address constant RECIPIENT = address(${recipient});`);
  console.log(`uint256 constant MERCHANT_COMMITMENT = ${F.toString(merchantCommitment)};`);
  console.log(`uint256 constant NOTE_COMMITMENT = ${F.toString(noteCommitment)};`);
  console.log(`uint256 constant NULLIFIER = ${F.toString(nullifier)};`);
  console.log(`uint256 constant MERKLE_ROOT = ${F.toString(merkleRoot)};`);
  console.log("");
  console.log("uint256[8] memory proof = [");
  for (let i = 0; i < 8; i++) {
    console.log(`    uint256(${solProof[i]})${i < 7 ? "," : ""}`);
  }
  console.log("];");

  // Verify locally
  const vkeyPath = resolve(__dirname, "build/verification_key.json");
  const vkey = JSON.parse(readFileSync(vkeyPath, "utf-8"));
  const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  console.log("\nLocal verification:", valid ? "✓ VALID" : "✗ INVALID");

  // Also output the zero hashes for Solidity verification
  console.log("\n// Zero hashes (for Solidity Poseidon tree init verification):");
  for (let i = 0; i < 3; i++) {
    console.log(`// zeros[${i}] = ${F.toString(zeros[i])}`);
  }
}

main().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1); });
