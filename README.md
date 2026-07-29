# ZKAuth — Offline Zero-Knowledge Identity Verifier

> Privacy-preserving identity verification for Android — no blockchain, no internet required.

![Status](https://img.shields.io/badge/Status-Complete-success)
![Tech](https://img.shields.io/badge/Built%20With-Rust%20%7C%20Kotlin%20%7C%20Plonky2-orange)
![Performance](https://img.shields.io/badge/Performance-20ms%20Verify-brightgreen)

## Overview
ZKAuth is a **Final Year Project (FYP)** demonstrating a novel approach to digital identity. It uses **Zero-Knowledge Proofs (ZKPs)**, generated and verified entirely on-device via a custom **Rust-based native engine** (linked to Android through JNI), to prove identity claims without exposing personal data or requiring internet access.

The system is built around three independent circuits, each with its own security engineering history (see version notes in source):

| Tier | Circuit | Trust Source | What it Proves |
| :--- | :--- | :--- | :--- |
| **[Tier 1 — Passport](TIER1_PASSPORT.md)** | `passport_security.rs` (v5.1) | Government-signed NFC passport chip (ICAO 9303) | `is_human`, `is_adult`, `nationality`, `passport_valid` |
| **Tier 2 — National ID** | *coming soon* | NFC CNIC / Aadhaar | `age`, `nationality` |
| **[Tier 3 — Device](TIER3_DEVICE.md)** | `device_tier.rs` (v2.0) | Phone's fingerprint sensor + hardware KeyStore | `is_human`, `is_real_device`, `is_unique`, `account_age_ok` |

Once an identity is established via Tier 1, it can be broadcast to a nearby device **fully offline** via a QR-stream protocol — see [OFFLINE_IDENTITY.md](OFFLINE_IDENTITY.md) for how that transmission layer works, its architecture, and performance benchmarks.

---

## Tech Stack

* **Core Logic:** Rust (Plonky2 library)
* **Mobile Bridge:** JNI (Java Native Interface)
* **Android UI:** Kotlin + Jetpack Compose + ZXing (QR streaming)
* **Build Tool:** Cargo NDK
* **Backend:** Node.js relay (Railway) for cross-device login verification

---

## ⭐ Support This Project

If you find this useful, consider giving it a star — it helps a lot and keeps the project visible to others working on ZK identity!

---

## How to Build

### Prerequisites
1. Install **Rust** & **Cargo**.
2. Install **Android Studio** & **NDK**.
3. Install `cargo-ndk`:
```bash
   cargo install cargo-ndk
```

### Compilation Steps
1. **Compile Rust library:**
```bash
   cd Zkp-App/android/rust
   cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build --release
```
2. **Build Android APK:**
   Open the project in Android Studio and hit **Run (▶)**.

---

## License
This project is dual-licensed under MIT or Apache-2.0, at your option.