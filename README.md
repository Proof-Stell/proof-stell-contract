

# ProofStell Smart Contract

Decentralized Document Verification Contract built with Soroban.

This contract powers the on-chain verification layer of the ProofStell platform, allowing institutions and individuals to register and verify document authenticity on the Stellar blockchain.

The contract stores cryptographic hashes of documents to ensure that document authenticity can be verified without exposing the actual document contents.

This approach ensures privacy, security, and immutability while enabling global verification.

---

## Overview

ProofStell provides a decentralized registry for documents such as:

• Academic certificates  
• Employment letters  
• Compliance certificates  
• Training credentials  
• Legal documents  

Instead of storing full documents on-chain, the system stores a **cryptographic hash** of the document.

A document hash acts like a digital fingerprint.

If the document is modified in any way, its hash changes, making tampering immediately detectable.

This ensures:

• Document integrity  
• Privacy preservation  
• Tamper-proof verification  

---

## How It Works

1. An issuer uploads a document through the ProofStell platform.

2. The document is hashed using SHA256.

3. The hash is sent to the Soroban smart contract.

4. The smart contract stores the hash with metadata including:
   - issuer address
   - owner address
   - timestamp
   - revocation status

5. Anyone can later verify the document by hashing the file and checking the blockchain record.

---

## Contract Data Model

The contract maintains a registry mapping document hashes to document records.

DocumentHash → DocumentRecord


Security Considerations

The contract implements several safeguards:

Hash-Based Storage
Documents are never stored on-chain. Only hashes are stored.

Issuer Authorization
Only authorized issuers should be allowed to register credentials.

Duplicate Protection
A document hash cannot be registered twice.

Revocation Control
Issuers retain the ability to revoke documents.

Immutability
Once stored, records cannot be altered.

Development
Requirements
• Rust
• Soroban CLI
• Stellar Testnet

Install Soroban CLI
cargo install soroban-cli

Build contract
cargo build --target wasm32-unknown-unknown --release

Deploy contract

soroban contract deploy \
--wasm target/wasm32-unknown-unknown/release/proofstell_contract.wasm \
--network testnet
Future Improvements

• Issuer registry system
• Credential NFTs
• Zero-knowledge document proofs
• Multi-signature issuer verification
• Public verification explorer
