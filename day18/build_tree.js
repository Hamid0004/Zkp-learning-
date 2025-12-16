const circomlibjs = require('circomlibjs');

async function main() {
    const poseidon = await circomlibjs.buildPoseidon();
    
    // Helper function hash ko string banane ke liye
    const F = poseidon.F;
    const hash = (left, right) => F.toString(poseidon([left, right]));

    // 1. Chaar Users (Leaves)
    const leaf1 = 111; // Hum (User A)
    const leaf2 = 222; // User B
    const leaf3 = 333; // User C
    const leaf4 = 444; // User D

    console.log("Leaves:", [leaf1, leaf2, leaf3, leaf4]);

    // 2. Level 1 Hashes (Branches)
    // Hash(111, 222) -> H1
    const h1 = hash(leaf1, leaf2);
    // Hash(333, 444) -> H2
    const h2 = hash(leaf3, leaf4);

    // 3. Level 2 Hash (ROOT)
    // Hash(H1, H2) -> Root
    const root = hash(h1, h2);

    console.log("--------------------------------");
    console.log("Calculated Root:", root);
    console.log("--------------------------------");

    // 4. Input Generate karo (User A ke liye proof)
    // User A (111) ke liye:
    // Partner 1: 222 (Right side par hai) -> Index 0 (Hum Left hain)
    // Partner 2: H2  (Right side par hai) -> Index 0 (Humara group Left tha)
    
    const input = {
        "leaf": "111",
        "path_elements": [leaf2.toString(), h2.toString()], // Pehle 222 mila, phir H2 mila
        "path_index": ["0", "0"], // Hum dono baar Left side par thay
        "root": root
    };

    console.log("PASTE THIS IN input.json:");
    console.log(JSON.stringify(input, null, 2));
}

main();