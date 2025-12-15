pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

template AgeVerify() {
    // 1. INPUTS
    signal input dob;           // Private (Secret: 2000)
    signal input cutoff;        // Public (Rule: 2006)
    signal input stored_hash;   // Public (Identity Check)

    // 2. OUTPUT
    signal output is_valid;

    // --- LOGIC 1: HASH CHECK (Identity) ---
    // Pehle check karo ke user ne apna ASLI DOB diya hai ya nahi
    component hasher = Poseidon(1);
    hasher.inputs[0] <== dob;
    
    // STRICT CONSTRAINT: Agar Hash match nahi hua, to Circuit Fail!
    hasher.out === stored_hash; 

    // --- LOGIC 2: RANGE CHECK (Age) ---
    // Ab check karo ke wo 18+ hai ya nahi
    component lt = LessThan(32);
    lt.in[0] <== dob;
    lt.in[1] <== cutoff;

    // Final Result (1 = Adult, 0 = Underage)
    is_valid <== lt.out;
}

// Main component: cutoff aur stored_hash public rahenge
component main {public [cutoff, stored_hash]} = AgeVerify();