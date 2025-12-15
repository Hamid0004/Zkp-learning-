const circomlibjs = require('circomlibjs');

async function main() {
    const poseidon = await circomlibjs.buildPoseidon();
    // DOB = 2000 ka hash nikalo
    const hash = poseidon.F.toString(poseidon([2001]));
    console.log("Hash for 2000:", hash);
}

main()