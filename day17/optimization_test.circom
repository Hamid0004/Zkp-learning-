pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

// ❌ BAD WAY (Heavy Circuit)
// Hum 252 bits use kar rahe hain jabke number chota hai
template HeavyCircuit() {
    signal input in;
    signal output out;

    // 252 bits = Bohot saare constraints (wires)
    component lt = LessThan(252); 
    
    lt.in[0] <== in;
    lt.in[1] <== 100;
    
    out <== lt.out;
}

// ✅ GOOD WAY (Light Circuit)
// Hum sirf 8 bits use kar rahe hain (0-255 range)
template LightCircuit() {
    signal input in;
    signal output out;

    // Sirf 8 bits = Kam constraints
    component lt = LessThan(8); 
    
    lt.in[0] <== in;
    lt.in[1] <== 100;
    
    out <== lt.out;
}

// ABHI HUM "HEAVY" WALE KO TEST KARENGE
//component main = HeavyCircuit();
// abh hum light circut test karenge 
component main = LightCircuit();