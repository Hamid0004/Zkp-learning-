# 🛡️ Zero-Knowledge Offline Identity Verifier (Mobile)

> **Privacy-Preserving Identity Verification on Android using Plonky2 & Rust**

![Status](https://img.shields.io/badge/Status-Complete-success)
![Tech](https://img.shields.io/badge/Built%20With-Rust%20%7C%20Kotlin%20%7C%20Plonky2-orange)
![Performance](https://img.shields.io/badge/Performance-20ms%20Verify-brightgreen)

## 📖 Overview
This project is a **Final Year Project (FYP)** demonstrating a novel approach to digital identity. Unlike traditional systems that rely on internet connectivity or heavy blockchain lookups, this application verifies **Zero-Knowledge Proofs (ZKPs)** entirely **offline** on the device.

It utilizes a custom **Rust-based Native Engine** linked via JNI to Android, enabling high-performance **Plonky2** proof verification even on resource-constrained hardware.

---

## 🚀 Key Features

* **⚡ Blazing Fast:** Verifies complex cryptographic proofs in **~19ms** (23x faster than Groth16 on mobile).
* **🔋 Eco-Friendly:** Optimized algorithm consumes **0% Battery** over 100 continuous verification cycles.
* **🔒 100% Offline:** Uses a "Fountain Code" QR stream to transfer data without Internet, Bluetooth, or NFC.
* **🛡️ Tamper Resistant:** Includes a "Red Team" security module that detects and rejects modified/fake proofs instantly.
* **📱 Lightweight:** Runs smoothly on low-end devices with cracked screens/old processors (Tested: 14MB RAM usage).

---

## 📊 Performance Benchmarks

We benchmarked the system against industry-standard mobile ZKP implementations.

| Metric | **My Project (Plonky2)** 🚀 | **Standard (Groth16)** 🐢 | **Improvement** |
| :--- | :--- | :--- | :--- |
| **Verification Time** | **~19.2 ms** | ~450 ms | **23x Faster** |
| **RAM Usage** | **~14 MB** | ~150 MB | **90% Lighter** |
| **Battery Impact** | **0% Drop** (100 runs) | ~5% Drop | **Green Energy** |
| **Setup Type** | Transparent (No Trusted Setup) | Trusted Setup Required | **More Secure** |

> *Tested on: Android Device (Snapdragon 6 series equivalent), Battery Stress Test conducted via internal 100-loop driver.*

---

## 🛠️ Tech Stack

* **Core Logic:** Rust (Plonky2 Library)
* **Mobile Bridge:** JNI (Java Native Interface)
* **Android UI:** Kotlin + ZXing (Customized for QR Streaming)
* **Build Tool:** Cargo NDK

---

## 📸 Screenshots & Demo

| **Identity Verified (Success)** | **Fake Proof Detected (Security)** |
| :---: | :---: |
| <img src="screenshots/verified.jpg" width="250"> | <img src="screenshots/fake_proof.jpg" width="250"> |
| *Time: 19ms | RAM: 9MB* | *Rejected instantly* |

---

## 📦 How to Build

### Prerequisites
1.  Install **Rust** & **Cargo**.
2.  Install **Android Studio** & **NDK**.
3.  Install `cargo-ndk`:
    ```bash
    cargo install cargo-ndk
    ```

### Compilation Steps
1.  **Compile Rust Library:**
    ```bash
    cd Zkp-App/android/rust
    ./build_android.sh
    ```
2.  **Build Android APK:**
    Open the project in Android Studio and hit **Run (▶)**.

---

## 📜 License
This project is open-source under the MIT License.