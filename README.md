# 📜 ProofStell Smart Contract

Decentralized document verification contract built with Soroban.

---

## 🌍 Overview

This smart contract powers the **on-chain verification layer** of ProofStell.

It stores **cryptographic hashes of documents** and enables:

* Document registration
* Verification
* Revocation

---

## 🚀 Core Features

### 📄 Document Registry

* Store document hashes on-chain
* Ensure immutability

---

### 🔎 Verification

* Check if a document exists
* Confirm authenticity

---

### 🧾 Revocation

* Allow issuers to revoke documents
* Maintain revocation state

---

## 🧠 How It Works

1. Document is hashed (SHA256)

2. Hash is submitted to contract

3. Contract stores:

   * Issuer address
   * Owner address
   * Timestamp
   * Status

4. Verification compares hash with stored record

---

## 🗂️ Data Model

```
DocumentHash → DocumentRecord
```

---

## 🔐 Security

* No raw documents stored on-chain
* Duplicate prevention
* Issuer authorization
* Immutable records
* Revocation tracking

---

## 🛠️ Tech Stack

* Rust
* Soroban SDK
* Stellar Network

---

## 🚀 Development

### Requirements

* Rust
* Soroban CLI

---

### Install Soroban CLI

```bash
cargo install soroban-cli
```

---

### Build Contract

```bash
cargo build --target wasm32-unknown-unknown --release
```

---

### Deploy Contract

```bash
soroban contract deploy \
--wasm target/wasm32-unknown-unknown/release/proofstell_contract.wasm \
--network testnet
```

---

## 🧪 Testing

```bash
cargo test
```

---

## 🧪 Future Improvements

* Issuer registry system
* Multi-signature verification
* Zero-knowledge proofs
* Credential NFTs

---

## 🎯 Goal

To provide a **trustless, immutable verification layer** for documents using blockchain.

---

**ProofStell Contract — Trust anchored on-chain.**
