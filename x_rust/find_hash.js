const circomlibjs = require('circomlibjs');

async function main() {
    // Poseidon machine start karo
    const poseidon = await circomlibjs.buildPoseidon();
    
    // 1234 ka hash nikalo
    const hash = poseidon.F.toString(poseidon([1234]));
    
    console.log("Aapka Sahi Hash Yeh Hai:");
    console.log(hash);
}

main();