# 🚀 CONTRIBUTING.md — ZKAuth Identity Contribution Guide

> **Build the future of privacy-preserving identity with us.**
>
> This document explains how ZKAuth works, where you can contribute, and most importantly—**what YOU envision for this project.**

> **Status:** Currently solo-maintained (final year project, actively developed). Looking for the first outside contributors — if that's you, welcome!

---

## 📋 Quick Navigation

- [What is ZKAuth?](#what-is-zkauth)
- [How It Works (Simplified)](#how-it-works-simplified)
- [Current Architecture](#current-architecture)
- [Where to Contribute](#where-to-contribute)
- [💡 Share Your Vision](#-share-your-vision)
- [Setup & Development](#setup--development)
- [Coding Standards](#coding-standards)

---

## What is ZKAuth?

**ZKAuth** is an offline identity verification system for Android that proves you are who you claim to be—**without revealing any personal data**.

### The Problem It Solves
- 🔐 Passwords are outdated and insecure
- 📱 Phone biometrics leak metadata to apps
- 🌍 KYC/identity systems collect excessive personal data
- ⚡ Cross-device login requires internet (not always available)
- 🏦 No global standard for privacy-first identity

### The Solution
- **Zero-Knowledge Proofs:** Prove claims (age, nationality, identity) without exposing data
- **Offline-First:** Works 100% offline—no internet, no blockchain
- **On-Device:** All computation happens on your phone (Rust + Plonky2 ZK circuits)
- **Multi-Tier:** Government passport (Tier 1), National ID (Tier 2 coming), device biometric (Tier 3)

### Key Stats
- ✅ **~19ms** proof verification, **~14 MB** memory footprint (internal benchmarks — see [OFFLINE_IDENTITY.md](OFFLINE_IDENTITY.md))
- ✅ **100% offline** cross-device verification via QR
- ✅ **Hash-based cryptography, not elliptic-curve pairings** (FRI-based via Plonky2) — avoids the assumptions Shor's algorithm is known to break, a promising property for post-quantum resistance, though not formally certified
- ✅ Designed with data minimization in mind (no raw personal data retained) — not a formal compliance certification

> Note: numbers above are our own internal benchmarks on test hardware, not an independently verified comparison against Groth16 or a legal compliance audit. Treat as directional, not certified.

---

## How It Works (Simplified)

### Tier 1: Government Passport 🛂

```
1. 📷 Scan passport's photo page with camera
   ↓
2. 📱 Tap phone to passport (NFC chip)
   ↓
3. 🔐 Encrypted handshake using ICAO 9303 standard
   ↓
4. ✅ Verify government's digital signature
   ↓
5. ⚙️ Generate Plonky2 zero-knowledge proof (~80ms)
   ↓
6. 📤 Share proof (not personal data) with website
   ↓
✅ Website grants access (banking, age verification, etc.)
```

**What the proof proves:** "I am human, 18+, from [country], passport valid"
**What is hidden:** Name, exact DOB, passport number, passport photo

---

### Tier 3: Device Biometric 👆

```
1. 👆 Scan fingerprint/face on phone
   ↓
2. 🔑 Access device's encrypted identity key
   ↓
3. ⚙️ Generate Plonky2 proof (~100ms)
   ↓
4. 📤 Share proof (not biometric template)
   ↓
✅ Proves: "This is a real device, unique, genuinely mine"
   (Great for passwordless login, CAPTCHA replacement)
```

---

### Cross-Device QR Verification 📲

```
Device A (Prover)              Device B (Verifier)
├─ Generate proof              ├─ Open camera
├─ Encode as multi-phase QR    ├─ Scan QR stream
├─ Cycle: FWD → RWD → RND      ├─ Reconstruct proof
└─ Display (no internet)       ├─ Verify locally (5ms)
                               └─ ✅ or ❌ result
```

**No internet required. No central server. Just math.**

---

## Current Architecture

### Tech Stack Overview

| Layer | Technology | Why? |
|:------|:-----------|:-----|
| **ZK Circuits** | Plonky2 (Rust) | Fast (~80ms), transparent (no trusted setup), post-quantum friendly |
| **Mobile UI** | Kotlin + Jetpack Compose | Modern, reactive, performant Android development |
| **JNI Bridge** | cargo-ndk | Seamless Rust↔Kotlin communication |
| **NFC** | ICAO 9303 BAC | International standard, 150+ countries supported |
| **Cryptography** | SHA-256, Poseidon, RSA/ECDSA | Government-grade, ZK-optimized |
| **Storage** | Android KeyStore + AES-256-GCM | Hardware-backed encryption |
| **Backend** | Node.js + Express (Railway) | Simple cross-device verification relay |

### Directory Structure

```
zkp-identity/
├── Zkp-App/android/
│   ├── rust/
│   │   └── src/
│   │       ├── passport_security.rs  ← Tier 1 (Government passport)
│   │       ├── device_tier.rs        ← Tier 3 (Device biometric)
│   │       ├── offline_identity.rs   ← QR proof transmission
│   │       └── proof_bench.rs        ← Performance benchmarking
│   └── app/
│       └── src/main/java/com/example/zkpapp/
│           ├── PassportActivity.kt   ← Tier 1 UI
│           ├── DeviceTierGate.kt     ← Tier 3 UI
│           ├── SecurityGate.kt       ← Rust JNI bridge
│           ├── IdentityStorage.kt    ← Encrypted storage
│           └── ...
├── backend/
│   ├── server.js                     ← Express relay
│   ├── verify-proof.js               ← Proof verification
│   └── public/
│       └── index.html                ← Dashboard
├── TIER1_PASSPORT.md                 ← Tier 1 spec & security
├── TIER3_DEVICE.md                   ← Tier 3 spec
├── OFFLINE_IDENTITY.md               ← QR protocol
├── SECURITY.md                       ← Threat model & defense
└── README.md
```

### Core Circuits (Simplified)

**Tier 1: Passport Proof**
```
Private (Prover only):          Public (Anyone can verify):
├─ Passport data (DG1)          ├─ Merkle root
├─ Govt signature               ├─ Nullifier (replay protection)
├─ DOB, nationality             └─ Valid timestamp
└─ Merkle tree path

Constraints:
✓ Merkle proof is valid
✓ Age >= 18 (range check)
✓ Nationality matches
✓ Government signature valid
```

**Tier 3: Device Proof**
```
Private:                         Public:
├─ Biometric template          ├─ Device binding (hw-backed)
├─ Device ID                   ├─ Nullifier (domain-scoped)
├─ Account creation date       ├─ Merkle root
└─ Challenge (server nonce)    └─ Proof of uniqueness

Constraints:
✓ Biometric exists (not zero)
✓ Device is real (attestation valid)
✓ Account age >= 30 days
✓ Proof hasn't been replayed
```

---

## Where to Contribute

### 🟢 Beginner-Friendly

**Good first issues:**
- [ ] **Docs:** Expand README with diagrams, add troubleshooting guide
- [ ] **Testing:** Write unit tests for MRZ (Machine Readable Zone) parsing
- [ ] **UI Polish:** Improve MRZ camera overlay, add dark mode
- [ ] **Localization:** Translate UI strings to other languages
- [ ] **Bug Reports:** Test on various Android devices (report NFC issues)

### 🟡 Intermediate

**Feature development:**
- [ ] **Tier 2 — National ID:** Add NFC CNIC (Pakistan) or Aadhaar (India) support
- [ ] **Performance:** Optimize circuit size or memory usage
- [ ] **Error Handling:** Improve NFC timeout/retry logic
- [ ] **QR Improvements:** Add error correction, increase throughput
- [ ] **Security Hardening:** Fuzz-test passport parser, audit circuits
- [ ] **Backend Scaling:** Multi-tenant proof verification

### 🔴 Advanced

**Major initiatives:**
- [ ] **iOS Support:** Port to Apple with equivalent security
- [ ] **Post-Quantum Crypto:** Formal analysis of quantum resistance
- [ ] **OAuth/OpenID:** "Login with ZKAuth" web integration
- [ ] **Decentralized Keys:** On-chain issuer registry (no hardcoded gov keys)
- [ ] **Privacy Enhancements:** Age ranges (prove "18–25" without DOB), liveness detection
- [ ] **Enterprise:** KYC/AML integration, compliance reporting

---

## 💡 Share Your Vision

**This is where YOU come in.**

We're not trying to predict the future—we want to hear **your ideas** about where ZKAuth should go. Whether you're:

- 🏗️ A developer with a killer feature idea
- 🔒 A security researcher thinking about new threat models
- 🌍 A policy expert thinking about GDPR/regulation alignment
- 🎨 A UX designer imagining better flows
- 💼 An entrepreneur seeing a business angle
- 🔬 An academic interested in cryptography research

**...we want to hear from you.**

### How to Share Ideas

**Option 1: GitHub Discussions** (Recommended)
1. Go to [Discussions](https://github.com/Hamid0004/zkp-identity/discussions)
2. Click "New discussion" → Choose "Ideas"
3. Describe your vision:
   - **Title:** Clear, concise
   - **Problem:** What's missing or broken?
   - **Solution:** Your idea (can be rough)
   - **Impact:** Why would this matter?
   - **Difficulty:** (Rough estimate: easy/medium/hard)

**Option 2: Open an Issue**
1. GitHub Issues → "New issue"
2. Use label `[Enhancement]` or `[RFC]` (Request for Comments)
3. Follow same format as above

**Option 3: Reach Out Directly**
- X/Twitter: [@hamidiqbal369](https://x.com/hamidiqbal369)
- Subject line if messaging: "ZKAuth Idea: [Your Idea]"

### Example Ideas We'd Love to Hear

- **Privacy:** "How could we prove age without revealing exact DOB?"
- **Performance:** "Could we compress proofs further with recursive circuits?"
- **Scale:** "How to verify millions of proofs without a central server?"
- **Accessibility:** "Could blind users prove identity with voice instead of face?"
- **Business:** "How to monetize this without collecting data?"
- **Security:** "What new threat model should we defend against?"
- **Integration:** "How could this work with banking APIs?"
- **Regulation:** "How to ensure GDPR/HIPAA compliance?"

**Every idea gets discussed. Best ideas might become features.**

---

## Setup & Development

### Prerequisites

```bash
# Rust toolchain (nightly)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly

# Android Studio (Iguana+)
# - Download: https://developer.android.com/studio
# - Install NDK via SDK Manager

# Cargo NDK (for Rust→ARM64 compilation)
cargo install cargo-ndk
```

### Build from Source

```bash
# 1. Clone
git clone https://github.com/Hamid0004/zkp-identity.git
cd zkp-identity

# 2. Compile Rust library to .so
cd Zkp-App/android/rust
cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build --release

# 3. Open in Android Studio
cd ../..
open .  # or manually: File → Open → select project root

# 4. Run on device/emulator
# Inside Android Studio: Run → Run 'app' (or press Shift+F10)

# 5. Deploy backend (optional)
cd backend
npm install
npm run start  # Local testing
npm run deploy # To Railway
```

### Development Workflow

```bash
# Make changes
git checkout -b feature/my-idea

# Test locally
cargo test --release                    # Rust tests
./gradlew connectedAndroidTest          # Android tests

# Format code
cargo fmt --all
./gradlew spotlessApply                 # Kotlin formatting

# Check for issues
cargo clippy -- -D warnings
./gradlew lint

# Commit
git add .
git commit -m "feat: brief description"

# Push & open PR
git push origin feature/my-idea
# Open PR on GitHub → describe changes → wait for review
```

### Debugging

```bash
# View Rust logs
adb logcat | grep "RustZKP"

# View Kotlin logs
adb logcat | grep "ZKAuth"

# Profile memory
./gradlew profileDebugBuild

# Test on low-end device
# (Use emulator with Snapdragon 600 series profile)
```

---

## Coding Standards

### Rust

**Format & Lint:**
```bash
cargo fmt --all
cargo clippy -- -D warnings
```

**Security:**
- Use `zeroize` crate for sensitive data
- Return `Result<T, E>` (not unwrap/panic)
- Validate all JNI inputs

**Documentation:**
```rust
/// Generates a zero-knowledge proof of age >= 18.
///
/// # Arguments
/// * `passport_data` - Encrypted passport data from storage
/// * `domain` - Verifier domain (for replay protection)
///
/// # Returns
/// ZK proof (valid for 300 seconds)
///
/// # Errors
/// Returns `Err` if passport data is invalid or corrupted
pub fn generate_age_proof(passport_data: &[u8], domain: &str) -> Result<ZkProof> {
    // ...
}
```

### Kotlin

**Format & Style:**
```bash
./gradlew spotlessApply
```

**Best Practices:**
- Use `suspend` for JNI calls (not blocking)
- Handle nullability with `?.let { }` or `?:` operator
- Avoid `!!` operator (prefer safe alternatives)
- Use `viewLifecycleOwner` scope for UI updates

**Example:**
```kotlin
lifecycleScope.launch(Dispatchers.Default) {
    when (val result = securityGate.generateProof(passportData)) {
        is ProofResult.Success -> {
            withContext(Dispatchers.Main) {
                displayProof(result.data)
            }
        }
        is ProofResult.Error -> showError(result.message)
    }
}
```

### Commits

```
[type] brief description under 50 chars

Optional longer explanation
- What changed
- Why it changed
- Any trade-offs

Fixes #123
```

**Types:** `feat`, `fix`, `docs`, `test`, `perf`, `refactor`, `chore`, `security`

---

## Community & Support

### Getting Help

- **Questions?** → Open a GitHub Discussion
- **Found a bug?** → Open an Issue with `[Bug]` label
- **Security issue?** → Email maintainer (don't public disclose)
- **Design feedback?** → Comment on existing issues/PRs

### Communication Guidelines

- Be respectful and inclusive
- Assume good intent
- Provide context and examples
- Link relevant issues/PRs

---

## License & Ownership

This project is **MIT Licensed** — anyone can use, modify, fork.

**Your contributions** become part of the project. We ask that you:
- Confirm your code is your own or properly licensed
- Allow your contributions to be used under MIT license
- Don't include personal data in commits

---

## Roadmap (Let's Build It Together)

**What we know:**
- ✅ v1.0 Beta — Tier 1 (passport) + Tier 3 (device) working
- 📅 v1.1 — OAuth integration, web SDK
- 📅 v2.0 — Tier 2 (National ID), iOS port

**What we DON'T know (yet):**
- Should we add AI-powered liveness detection? (Prevents deepfakes)
- Blockchain integration for issuer registry? (Decentralized keys)
- Marketplace for identity claims? (User privacy + monetization)
- Offline identity chain? (No internet ever needed)
- Post-quantum cryptography upgrade?
- Enterprise KYC/AML integration?
- Something completely different we haven't thought of?

**The answer is: it depends on what YOU think.**

---

## Let's Build the Future

ZKAuth started as a final year project. It's evolved into something bigger—a vision of **privacy-first, decentralized identity for everyone**.

But it's not complete. It's not even close.

**We need builders, thinkers, and dreamers.**

If you see a future where:
- ✅ You control your identity (not companies or governments)
- ✅ You prove claims without revealing data
- ✅ You use one identity everywhere (banking, voting, services)
- ✅ The system works offline, offline-first, resilient
- ✅ Privacy is the default, not an option

**...then there's a place for you here.**

---

### Questions?

1. **How do I get started?** Pick an issue from "Good First Issues" or share your idea in Discussions.
2. **Do I need cryptography knowledge?** No—start with docs/UI improvements, work your way up.
3. **Can I work on my own idea?** Absolutely. Open a Discussion first so we can align.
4. **What if my PR gets rejected?** All feedback is learning. We'll explain why and suggest alternatives.
5. **How long until my code is merged?** Depends on complexity—typically 1-3 weeks for review.

---

## Contributors We're Looking For

- 🦀 **Rust engineers** (Plonky2, cryptography)
- 📱 **Android developers** (Kotlin, JNI, NFC)
- 🔐 **Security researchers** (threat modeling, audits)
- 🌐 **Web developers** (OAuth, SDK, integration)
- 📝 **Technical writers** (docs, tutorials)
- 🎨 **UX designers** (flows, testing, accessibility)
- 🏗️ **DevOps** (CI/CD, deployment, scaling)
- 🧠 **Product managers** (roadmap, prioritization)
- 💼 **Business strategists** (partnerships, go-to-market)

**All skill levels welcome.** We'll help you learn.

---

## Final Thought

> **"No passwords. No data. Just math."**

The future of identity isn't about collecting more personal information—it's about proving what matters, *without* revealing what doesn't.

Let's build it together.

**Ready to contribute?** Start here:
1. Read the code (especially TIER1_PASSPORT.md, TIER3_DEVICE.md)
2. Pick an area that excites you
3. Open a Discussion with your idea
4. Submit a PR (we're here to help)

---

**Questions? Feedback? Ideas?**

- **GitHub:** [@Hamid0004](https://github.com/Hamid0004)
- **Discussions:** [Project Discussions](https://github.com/Hamid0004/zkp-identity/discussions)
- **Issues:** [GitHub Issues](https://github.com/Hamid0004/zkp-identity/issues)

**Let's build the future of identity. 🚀**
