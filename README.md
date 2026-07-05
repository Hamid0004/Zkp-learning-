# Zero-Knowledge Offline Identity Verifier (Mobile)

> Privacy-Preserving Identity Verification on Android using Plonky2 & Rust

![Status](https://img.shields.io/badge/Status-Complete-success)
![Tech](https://img.shields.io/badge/Built%20With-Rust%20%7C%20Kotlin%20%7C%20Plonky2-orange)
![Performance](https://img.shields.io/badge/Performance-20ms%20Verify-brightgreen)

## Overview
This project is a **Final Year Project (FYP)** demonstrating a novel approach to digital identity. Unlike traditional systems that rely on internet connectivity or heavy blockchain lookups, this application verifies **Zero-Knowledge Proofs (ZKPs)** entirely **offline** on the device.

It utilizes a custom **Rust-based Native Engine** linked via JNI to Android, enabling high-performance **Plonky2** proof verification even on resource-constrained hardware.

---

## Key Features

* **Fast Verification:** Verifies cryptographic proofs in **~19ms**.
* **Eco-Friendly:** Consumes **0% Battery** over 100 continuous verification cycles.
* **100% Offline:** Uses a "Fountain Code" QR stream to transfer data without Internet, Bluetooth, or NFC.
* **Tamper Resistant:** Includes a security module that detects and rejects modified/fake proofs instantly.
* **Lightweight:** Runs on low-end and older Android devices (Tested: ~14MB RAM usage).

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

## Tech Stack

* **Core Logic:** Rust (Plonky2 library)
* **Mobile Bridge:** JNI (Java Native Interface)
* **Android UI:** Kotlin + ZXing (customized for QR streaming)
* **Build Tool:** Cargo NDK

---

## Screenshots & Demo

| **Identity Verified (Success)** | **Fake Proof Detected (Security)** |
| :---: | :---: |
| <img src="screenshots/verified.jpg" width="250"> | <img src="screenshots/fake_proof.jpg" width="250"> |
| *Time: 19ms · RAM: 9MB* | *Rejected instantly* |

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
This project is open-source under the MIT License.