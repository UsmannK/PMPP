pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./node_modules/circomlib/circuits/mux1.circom";

// Merkle proof checker using Poseidon(2) hash
template MerkleProof(depth) {
    signal input leaf;
    signal input pathIndices[depth];  // 0 = left, 1 = right
    signal input siblings[depth];
    signal output root;

    signal hashes[depth + 1];
    hashes[0] <== leaf;

    component hashers[depth];
    component mux[depth][2];

    for (var i = 0; i < depth; i++) {
        // pathIndices[i] must be 0 or 1
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // If pathIndices[i] == 0, leaf is left child: hash(current, sibling)
        // If pathIndices[i] == 1, leaf is right child: hash(sibling, current)
        mux[i][0] = Mux1();
        mux[i][0].c[0] <== hashes[i];
        mux[i][0].c[1] <== siblings[i];
        mux[i][0].s <== pathIndices[i];

        mux[i][1] = Mux1();
        mux[i][1].c[0] <== siblings[i];
        mux[i][1].c[1] <== hashes[i];
        mux[i][1].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i][0].out;
        hashers[i].inputs[1] <== mux[i][1].out;
        hashes[i + 1] <== hashers[i].out;
    }

    root <== hashes[depth];
}

// Main circuit: prove knowledge of note preimage + Merkle membership
// Public inputs: nullifier, merkleRoot, amount, asset, recipient
// Private inputs: everything else
template NoteRedeem(treeDepth) {
    // --- Public inputs ---
    signal input nullifier;
    signal input merkleRoot;
    signal input amount;
    signal input asset;
    signal input recipient;

    // --- Private inputs ---
    signal input merchantPubKey;
    signal input blinding;
    signal input noteRandomness;
    signal input channelId;
    signal input pathIndices[treeDepth];
    signal input siblings[treeDepth];

    // 1. merchantCommitment = Poseidon(merchantPubKey, blinding)
    component mcHash = Poseidon(2);
    mcHash.inputs[0] <== merchantPubKey;
    mcHash.inputs[1] <== blinding;
    signal merchantCommitment;
    merchantCommitment <== mcHash.out;

    // 2. noteCommitment = Poseidon(asset, amount, merchantCommitment, channelId, noteRandomness)
    component ncHash = Poseidon(5);
    ncHash.inputs[0] <== asset;
    ncHash.inputs[1] <== amount;
    ncHash.inputs[2] <== merchantCommitment;
    ncHash.inputs[3] <== channelId;
    ncHash.inputs[4] <== noteRandomness;
    signal noteCommitment;
    noteCommitment <== ncHash.out;

    // 3. Verify nullifier = Poseidon(noteCommitment, merchantPubKey)
    component nullHash = Poseidon(2);
    nullHash.inputs[0] <== noteCommitment;
    nullHash.inputs[1] <== merchantPubKey;
    nullifier === nullHash.out;

    // 4. Verify Merkle membership
    component merkle = MerkleProof(treeDepth);
    merkle.leaf <== noteCommitment;
    for (var i = 0; i < treeDepth; i++) {
        merkle.pathIndices[i] <== pathIndices[i];
        merkle.siblings[i] <== siblings[i];
    }
    merkleRoot === merkle.root;

    // 5. Constrain recipient (prevent front-running proof substitution)
    signal recipientSquare;
    recipientSquare <== recipient * recipient;
}

component main {public [nullifier, merkleRoot, amount, asset, recipient]} = NoteRedeem(20);
