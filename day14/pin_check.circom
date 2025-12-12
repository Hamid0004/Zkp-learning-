pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

template PinCheck() {
    // 1. Inputs
    signal input pin;          // Secret PIN
    signal input stored_hash;  // Public Hash

    // 2. Hash Machine
    component hasher = Poseidon(1);
    hasher.inputs[0] <== pin;

    // 3. Constraint (Check)
    hasher.out === stored_hash;
}

component main {public [stored_hash]} = PinCheck();