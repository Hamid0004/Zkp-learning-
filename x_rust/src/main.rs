// 1. STRUCT: Data Container
struct ZkCircuit {
    secret_pin: u32,  // Witness
    public_hash: u32, // Public Input
}

// 2. IMPL: Methods (Logic)
impl ZkCircuit {
    // Constructor: Naya circuit banane ke liye
    fn new(pin: u32, hash: u32) -> Self {
        ZkCircuit {
            secret_pin: pin,
            public_hash: hash,
        }
    }

    // 3. RESULT: Error Handling
    // Yeh function ya to true dega (Ok) ya error string (Err)
    fn verify(&self) -> Result<String, String> {
        // Simple logic: Maan lo hash bas PIN * 2 hai
        let calculated_hash = self.secret_pin * 2;

        if calculated_hash == self.public_hash {
            Ok("✅ Proof Verified!".to_string())
        } else {
            Err("❌ Invalid Proof: Hash match nahi hua.".to_string())
        }
    }
}

fn main() {
    // Step A: Struct banana
    let my_circuit = ZkCircuit::new(100, 200);

    // Step B: Method call karna aur Result handle karna
    // 'match' use karte hain Result kholne ke liye
    match my_circuit.verify() {
        Ok(message) => println!("{}", message), // Agar sahi hua
        Err(error) => println!("Error aaya: {}", error), // Agar ghalat hua
    }
}