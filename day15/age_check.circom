pragma circom 2.0.0;

// Circom ki library se comparison tools mangwana
include "node_modules/circomlib/circuits/comparators.circom";

template AgeCheck() {
    // 1. Inputs
    signal input dob;        // Private (User ka Secret)
    signal input cutoff;     // Public (Rule: 2006)

    // 2. Output (Result)
    signal output is_adult;

    // 3. Logic: LessThan(32)
    // 32 ka matlab hai hum 32-bit numbers compare kar rahe hain
    // (Jo years ke liye kaafi hai)
    component lt = LessThan(32);

    lt.in[0] <== dob;
    lt.in[1] <== cutoff;

    // 4. Result Assignment
    // Agar dob < cutoff, toh lt.out = 1 (True)
    // Agar dob > cutoff, toh lt.out = 0 (False)
    is_adult <== lt.out;
}

// Main component start
component main {public [cutoff]} = AgeCheck();