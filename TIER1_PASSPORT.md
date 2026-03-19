# Tier 1 — Passport Identity 🛂

> **Maximum Trust** — Government-verified identity via NFC passport chip.

---

## 🌟 What is Tier 1?

Tier 1 utilizes your **physical passport's NFC chip** to generate a Zero-Knowledge (ZK) proof locally on your device. 

Your passport contains a government-signed chip adhering to the ICAO 9303 standard. ZKAuth reads this chip, verifies the government's cryptographic signature, and generates a Plonky2 ZK proof—**without your passport data ever leaving your phone.**

### The Architecture Flow
1. **Physical Passport** ➔ 
2. **NFC Chip Read** *(BAC authentication)* ➔ 
3. **SOD Verification** *(Government RSA/ECDSA signature)* ➔ 
4. **Plonky2 ZK Proof** *(Generated on-device)* ➔ 
5. **Server Verification** *(Receives proof + nullifier only)*.

---

## 🛡️ Privacy & Proofs

### What Tier 1 Proves (Public)
* ✅ **`is_human`** — A physical passport guarantees a real, government-verified human.
* ✅ **`is_adult`** — Age is mathematically proven to be ≥ 18 (derived from the DOB on the chip).
* ✅ **`nationality`** — Country of issue is verified (derived from the MRZ).
* ✅ **`passport_valid`** — Document is not expired, and the SOD signature is authentic.

### What is NEVER Revealed (Hidden)
* ❌ Full Name
* ❌ Exact Date of Birth
* ❌ Passport Number
* ❌ Exact Expiry Date
* ❌ Facial Photo
* ❌ Raw MRZ Data
* ❌ Document Signing Certificates

---

## ⚙️ How It Works (Under the Hood)

**Step 1: MRZ Scan**
The device camera scans the passport's photo page. OCR extracts the Machine Readable Zone (MRZ) to get the Document Number, Date of Birth, and Expiry Date.

**Step 2: NFC BAC Authentication**
The user taps the phone against the passport. Using Basic Access Control (BAC), session keys are derived from the MRZ to establish an encrypted channel with the chip.

**Step 3: Data Group Extraction**
* **DG1:** Personal data (Name, DOB, Nationality).
* **DG2:** Facial image biometric data.
* **SOD:** Document Security Object (Contains hashes of all DGs, signed by the issuing government).

**Step 4: SOD Verification**
The Document Signer Certificate is extracted. The app verifies that the DG1 hash matches the SOD, and validates the government's RSA/ECDSA signature.

**Step 5: ZK Proof Generation**
The Rust/Plonky2 circuit takes the DG1 data and SOD signature as private inputs. It outputs a ZK proof validating the age, nationality, and government signature, while keeping all raw values completely hidden.

---

## 📱 User Experience Flows

### Registration Flow
1. **Initiate:** App → Create ID → Select *Tier 1 — Passport*.
2. **Scan MRZ:** Camera scans the passport photo page.
3. **NFC Tap:** Hold the phone to the passport for ~3 seconds to complete chip authentication.
4. **Biometric Binding:** User scans fingerprint/FaceID to encrypt the passport data to the Android Keystore.
5. **Proof Generation:** ZK Proof is generated locally. 
6. **Completion:** ✅ Maximum Trust identity is ready for use.

### Authentication Flow (Login)
1. **Trigger:** Website displays a QR code or deep link.
2. **Launch:** ZKAuth app opens.
3. **Routing:** * *Path A:* Session is valid → Proof is generated directly.
   * *Path B:* Session expired → User provides biometric to unlock the vault → Proof is generated.
   * *Path C:* No identity found → Redirected to Registration Flow.
4. **Execution:** Plonky2 proof is generated (~2-4 sec).
5. **Verification:** App POSTs payload to `/zkauth/verify`. Website grants access.

---

## 🔐 Security Design

* **ICAO 9303 Compliance:** International standard for e-passports used by 150+ countries. Supports RSA-2048 and ECDSA.
* **Anti-Simulation:** Real NFC passport required. DG1 must be valid (≥ 180 hex chars). Simulated data is strictly rejected in production.
* **Replay Prevention:** Achieved via Poseidon hash nullifiers uniquely scoped per domain and challenge.
* **Proof TTL:** Proofs expire after 300 seconds (5 minutes).
* **Session TTL:** Plaintext data is wiped from RAM after 30 minutes.
* **Hardware Binding:** Encrypted using `AES-256-GCM` stored in the Android KeyStore.

---

## 🌍 Supported Passports

* ✅ Any ICAO 9303 compliant e-passport
* ✅ 150+ countries supported (Pakistan, India, UK, USA, EU, etc.)
* ✅ NFC chip required (Biometric passports)
* ✅ BAC (Basic Access Control) supported
* ⏳ *PACE (Password Authenticated Connection) — Coming soon*

---

## 📊 Trust Level Comparison

| Feature | Tier 1 (Passport) | Tier 3 (Device Only) |
| :--- | :--- | :--- |
| **Verified By** | Government (RSA/ECDSA) | Hardware Enclave (TEE) |
| **Identity Proven** | ✅ Yes | ❌ No |
| **Age Proven** | ✅ Yes | ❌ No |
| **Nationality Proven**| ✅ Yes | ❌ No |
| **Sybil Resistant** | ✅ Strong | ⚠️ Basic (Device ID) |
| **Use Case: Banking** | ✅ Yes | ❌ No |
| **Use Case: CAPTCHA** | ⚠️ Overkill | ✅ Yes |

---

## 🛠️ Technical Specifications

* **Circuit:** `passport_security.rs` (Plonky2)
* **Hashing:** Poseidon (Optimized for ZK-SNARKs)
* **NFC Protocol:** IsoDep + ICAO 9303 BAC
* **Encryption:** `AES-256-GCM` (Android KeyStore)
* **Signing:** ECDSA P-256 (Device hardware binding)
* **Proof Time:** ~2-4 seconds on modern ARM64 Android devices.

---
*Part of the ZKAuth — Zero-Knowledge Identity Protocol Suite*