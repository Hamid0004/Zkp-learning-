pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/mux1.circom";

// Helper Template: Do cheezon ko sahi order mein hash karna
template HashLeftRight() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    hash <== hasher.out;
}

// Helper Template: Order Decide karna (Left ya Right?)
// Agar path_index 0 hai -> (leaf, sibling)
// Agar path_index 1 hai -> (sibling, leaf)
template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    component mux1 = Mux1();
    mux1.c[0] <== in[0];
    mux1.c[1] <== in[1];
    mux1.s <== s;

    component mux2 = Mux1();
    mux2.c[0] <== in[1];
    mux2.c[1] <== in[0];
    mux2.s <== s;

    out[0] <== mux1.out;
    out[1] <== mux2.out;
}

// MAIN CIRCUIT: Merkle Verification (Level 2)
template MerkleProof(levels) {
    signal input leaf;              // Aapka Secret Data
    signal input path_elements[levels]; // Raste ke Partners (Neighbors)
    signal input path_index[levels];    // 0 = Left, 1 = Right
    signal input root;              // Public Top Hash

    component hashers[levels];
    component mux[levels];

    signal current_hash[levels + 1];
    current_hash[0] <== leaf;

    // Loop chalayenge Levels ke hisaab se
    for (var i = 0; i < levels; i++) {
        // Step 1: Decide karo Left kaun aur Right kaun
        mux[i] = DualMux();
        mux[i].in[0] <== current_hash[i];
        mux[i].in[1] <== path_elements[i];
        mux[i].s <== path_index[i];

        // Step 2: Hash karo
        hashers[i] = HashLeftRight();
        hashers[i].left <== mux[i].out[0];
        hashers[i].right <== mux[i].out[1];

        current_hash[i + 1] <== hashers[i].hash;
    }

    // Step 3: Final Check
    root === current_hash[levels];
}

// Hum 2 Level ka Tree bana rahe hain (4 Users)
component main {public [root]} = MerkleProof(2);