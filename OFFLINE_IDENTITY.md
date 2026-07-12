# Offline Identity Verification Engine

> The core Zero-Knowledge proof engine that powers ZKAuth — verifies identity entirely offline, on-device, using Plonky2.

---

## Overview
This is the heart of the project: a **Rust-based ZK proof engine**, linked via JNI to Android, that generates and verifies **Zero-Knowledge Proofs (ZKPs)** entirely **offline** — no internet connectivity or blockchain lookups required.

Both trust tiers ([Tier 1 — Passport](TIER1_PASSPORT.md) and [Tier 3 — Device](TIER3_DEVICE.md)) run on top of this same engine.

---

## Key Features

* **Fast Verification:** Verifies cryptographic proofs in **~19ms**.
* **Eco-Friendly:** Consumes **0% Battery** over 100 continuous verification cycles.
* **100% Offline:** Transfers proof data via a multi-phase QR stream — no Internet, Bluetooth, or NFC needed.
* **Tamper Resistant:** Includes a security module that detects and rejects modified/fake proofs instantly.
* **Lightweight:** Runs on low-end and older Android devices (Tested: ~14MB RAM usage).

---

## Architecture

The system uses a 3-layer design to keep cryptographic computation off the JVM:

1. **Presentation Layer (Kotlin/Android):** Camera capture, QR display, user feedback
2. **Bridge Layer (JNI):** Transfers raw byte arrays between the Android runtime and native memory
3. **Core Logic Layer (Rust + Plonky2):** Executes proof generation/verification directly on the ARM64 CPU

**Data flow (verification):**
Camera scans QR stream → JNI passes bytes to Rust →
Rust deserializes + verifies proof → Boolean result returned to UI

### QR Transmission Protocol
The proof (tens of KB) is too large for a single QR code, so it's split into
signed chunks and cycled through three phases — **forward, reverse, random**
— so a scanner that misses a frame in one pass can pick it up in the next.
No Bluetooth or NFC required.

### Why Plonky2 (not Groth16)
Plonky2 uses a FRI-based proving system, which means:
- **No trusted setup** — unlike Groth16, there's no ceremony required
- **Hash-based cryptography instead of elliptic-curve pairings** — this avoids
  the discrete-log/factoring assumptions that Shor's algorithm is known to
  break, a property widely considered promising for post-quantum resistance
  (though this implementation has not undergone formal post-quantum
  cryptanalysis or certification)

---

## Security & Reliability

- **Replay protection:** Every proof carries a nonce + timestamp. Proofs
  older than 300 seconds are automatically rejected, along with a check
  against future-dated timestamps (clock-manipulation resistance).
- **Tamper detection:** Each QR chunk is signed with a CRC32 + SHA256
  signature; the full proof also carries its own SHA256 integrity hash.
  Any corruption or tampering is caught before verification even runs.
- **Crash resilience:** Native Rust code runs inside `catch_unwind`, so a
  panic in the cryptographic layer returns a graceful error instead of
  crashing the app.
- **Timeouts:** Proof generation (30s) and verification (60s) are both
  bounded — the UI never hangs indefinitely on a stuck native call.
- **Wake lock handling:** Screen is kept on during active proof
  generation/transmission and released immediately afterward.

---

## Performance Benchmarks

Internal benchmarks comparing this implementation (Plonky2) against a standard Groth16 mobile setup:

| Metric | **Plonky2 (This Project)** | **Groth16 (Standard)** | **Improvement** |
| :--- | :--- | :--- | :--- |
| **Verification Time** | ~19.2 ms | ~450 ms | ~23x faster |
| **RAM Usage** | ~14 MB | ~150 MB | ~90% lighter |
| **Battery Impact** | 0% Drop (100 runs) | ~5% drop | Green Energy |
| **Setup Type** | Transparent (no trusted setup) | Trusted setup required | More secure |

> *Tested on: Android device (Snapdragon 6-series equivalent). Battery test conducted via internal 100-loop benchmark driver.*

---

## Screenshots & Demo

| **Identity Verified (Success)** | **Fake Proof Detected (Security)** |
| :---: | :---: |
| <img src="screenshots/verified.jpg" width="250"> | <img src="screenshots/fake_proof.jpg" width="250"> |
| *Time: 19ms · RAM: 9MB* | *Rejected instantly* |