# Tier 3 — Device + Biometric Identity 📱

> **Basic Trust** — Hardware-backed proof without any physical document.

---

## 🌟 What is Tier 3?

Tier 3 proves you are a **real human on a real device**—using only your phone's fingerprint sensor and hardware security chip. No passport, no ID card, and nothing physical is needed.

### The Architecture Flow
1. **Your Fingerprint** ➔ 
2. **Android KeyStore** *(Hardware-backed)* ➔ 
3. **4-Leaf Plonky2 Merkle Tree Circuit** ➔ 
4. **ZK Proof** *(Generated on-device)* ➔ 
5. **Server Verification** *(Receives proof + nullifier only)*.

---

## 🛡️ Privacy & Proofs

### What Tier 3 Proves (Public)
* ✅ **`is_human`** — Real biometric data ensures a real person (not a bot).
* ✅ **`is_real_device`** — Hardware KeyStore attestation guarantees a physical device (not an emulator).
* ✅ **`is_unique`** — Domain-scoped nullifier ensures one proof per site (sybil resistance).
* ✅ **`account_age_ok`** — Device registered > 30 days ago prevents fresh bot account farms.

### What is NEVER Revealed (Hidden)
* ❌ Raw Fingerprint Data *(never leaves the secure enclave)*
* ❌ Actual Device ID
* ❌ Exact Account Age
* ❌ Name, Email, or Phone Number
* ❌ Cross-site Browsing History
* ❌ Any PII whatsoever

---

## 🌳 The 4-Leaf Merkle Tree Circuit

Tier 3 uses a **Plonky2 circuit** with 4 leaves—each leaf commits to one specific claim. The root commits to all 4 claims simultaneously. **Nothing is revealed—only the root is public.**

```text
              MERKLE ROOT
             /           \
         Node_L         Node_R
         /    \          /    \
      [Bio]  [Dev]   [Null]  [Age]