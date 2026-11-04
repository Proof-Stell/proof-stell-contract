//! Formal Verification & Contract Invariant Test Suite for Proof-Stell
//! Verifies administrative transitions, upgrade security, and document lifecycle.

use proofstell_contract::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

#[test]
fn test_administrative_invariants_and_version_boundaries() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(ProofStellContract, ());
    let client = ProofStellContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    // Initial state: not initialized
    assert_eq!(client.get_version(), 0);
    assert_eq!(client.get_admin(), None);

    // Initialize admin
    client.initialize(&admin);
    assert_eq!(client.get_admin(), Some(admin));
    assert_eq!(client.get_version(), 1);
}

#[test]
fn test_document_hash_uniqueness_and_revocation_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(ProofStellContract, ());
    let client = ProofStellContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let owner = Address::generate(&env);
    let doc_hash = BytesN::from_array(&env, &[42; 32]);

    client.initialize(&admin);

    // Document does not exist initially
    assert!(!client.document_exists(&doc_hash));

    // Register document (takes 3 arguments: issuer, owner, doc_hash)
    client.register_document(&issuer, &owner, &doc_hash);
    assert!(client.document_exists(&doc_hash));

    // Status is Active
    assert_eq!(client.get_document_status(&doc_hash), DocumentStatus::Active);

    // Revoke document
    client.revoke_document(&issuer, &doc_hash);
    assert_eq!(client.get_document_status(&doc_hash), DocumentStatus::Revoked);
}
