#![no_std]

// The service-side modules require std and are only available on non-WASM targets.
#[cfg(not(target_arch = "wasm32"))]
#[macro_use]
extern crate std;

#[cfg(not(target_arch = "wasm32"))]
pub mod cache;
#[cfg(not(target_arch = "wasm32"))]
pub mod config;

pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod event;
#[cfg(not(target_arch = "wasm32"))]
pub mod hash_validator;
#[cfg(not(target_arch = "wasm32"))]
pub mod metrics;
#[cfg(not(target_arch = "wasm32"))]
pub mod rate_limit;
#[cfg(not(target_arch = "wasm32"))]
pub mod stellar;
#[cfg(not(target_arch = "wasm32"))]
pub mod webhook;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, OnceLock};

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env,
    Symbol, Vec,
};

#[cfg(not(target_arch = "wasm32"))]
use crate::metrics::MetricsRegistry;

#[cfg(not(target_arch = "wasm32"))]
static RATE_LIMIT_METRICS: OnceLock<Arc<MetricsRegistry>> = OnceLock::new();

#[cfg(not(target_arch = "wasm32"))]
fn rate_limit_metrics() -> Arc<MetricsRegistry> {
    RATE_LIMIT_METRICS
        .get_or_init(|| Arc::new(MetricsRegistry::new()))
        .clone()
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_metrics() -> () {
    ()
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DocumentStatus {
    Active,
    Revoked,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentRecord {
    pub issuer: Address,
    pub owner: Address,
    pub timestamp: u64,
    pub status: DocumentStatus,
}

#[contracttype]
pub enum DataKey {
    Document(BytesN<32>),
    Admin,
    Version,
    FeatureFlag(Symbol),
    RateLimitConfig,
    RateLimitState(RateLimitScope),
    RateLimitRetryAfter(RateLimitScope),
}

pub const CONTRACT_VERSION: u32 = 1;

#[contracttype]
#[derive(Clone, Debug)]
pub struct DocumentInfo {
    pub owner: Address,
    pub document_hash: BytesN<32>,
}

pub const MAX_BATCH_SIZE: u32 = 20;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    pub per_address_per_second: u32,
    pub per_address_burst: u32,
    pub per_issuer_per_second: u32,
    pub per_issuer_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_address_per_second: 100,
            per_address_burst: 200,
            per_issuer_per_second: 100,
            per_issuer_burst: 200,
        }
    }
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitBucketState {
    pub tokens: u32,
    pub last_refill: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RateLimitScope {
    Address(Address),
    Issuer(Address),
}

/// Enumeration of all error conditions that can occur within the ProofStell contract.
///
/// Each variant maps to a unique numeric code for Soroban client interoperability,
/// allowing callers to distinguish failure cases and implement appropriate recovery logic.
///
/// # Error Codes
/// | Variant                | Code | Description                                              |
/// |------------------------|------|----------------------------------------------------------|
/// | `DocumentNotFound`     | 1    | No record exists for the given document hash             |
/// | `AlreadyRegistered`    | 2    | A document with this hash has already been registered    |
/// | `OnlyIssuerCanRevoke`  | 3    | The caller is not the original issuer of the document    |
/// | `AlreadyRevoked`       | 4    | The document has already been revoked                    |
/// | `InvalidOwner`         | 5    | The provided owner address is not valid for this op      |
/// | `InvalidIssuer`        | 6    | The provided issuer address is not valid for this op     |
/// | `BatchTooLarge`        | 7    | Batch exceeds the 20-document limit                      |
/// | `BatchEmpty`           | 8    | Batch input is empty                                     |
/// | `AlreadyInitialized`   | 9    | `initialize` called when contract is already initialized |
/// | `NotInitialized`       | 10   | Governance call before `initialize`                      |
/// | `Unauthorized`         | 11   | Caller is not the stored admin                           |
/// | `MigrationNotNeeded`   | 12   | Contract is already at the latest version                |
#[contracterror]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// No record exists for the provided document hash. Code: 1
    DocumentNotFound = 1,
    /// A document with this hash is already registered. Code: 2
    AlreadyRegistered = 2,
    /// The caller is not the original issuer and cannot perform this action. Code: 3
    OnlyIssuerCanRevoke = 3,
    /// The document has already been revoked and cannot be revoked again. Code: 4
    AlreadyRevoked = 4,
    /// The provided owner address failed validation. Code: 5
    InvalidOwner = 5,
    /// The provided issuer address failed validation. Code: 6
    InvalidIssuer = 6,
    /// The batch exceeds the maximum allowed size (20). Code: 7
    BatchTooLarge = 7,
    /// The batch is empty. Code: 8
    BatchEmpty = 8,
    /// The contract has already been initialized. Code: 9
    AlreadyInitialized = 9,
    /// The contract has not been initialized yet. Code: 10
    NotInitialized = 10,
    /// The caller is not the authorized admin. Code: 11
    Unauthorized = 11,
    /// The contract is already at the latest version; no migration is needed. Code: 12
    MigrationNotNeeded = 12,
    /// A rate-limit quota was exceeded for the caller. Code: 13
    RateLimitExceeded = 13,
}

#[contractevent(topics = ["register"], data_format = "vec")]
pub struct DocumentRegistered {
    #[topic]
    pub issuer: Address,
    pub owner: Address,
    pub document_hash: BytesN<32>,
}

#[contractevent(topics = ["revoke"], data_format = "vec")]
pub struct DocumentRevoked {
    #[topic]
    pub issuer: Address,
    pub document_hash: BytesN<32>,
}

#[contractevent(topics = ["init"], data_format = "vec")]
pub struct ContractInitialized {
    #[topic]
    pub admin: Address,
    pub version: u32,
}

#[contractevent(topics = ["upgrade"], data_format = "vec")]
pub struct ContractUpgraded {
    #[topic]
    pub admin: Address,
    pub old_version: u32,
    pub new_version: u32,
}

#[contract]
pub struct ProofStellContract;

#[contractimpl]
impl ProofStellContract {
    /// Registers a new document on-chain, associating it with an issuer and owner.
    ///
    /// The issuer must authorize this call. Each document hash can only be registered once.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `issuer`        - Address of the entity registering the document (must authorize)
    /// * `owner`         - Address of the document's owner
    /// * `document_hash` - 32-byte unique hash identifying the document
    ///
    /// # Returns
    /// The newly created [`DocumentRecord`] with `DocumentStatus::Active`
    ///
    /// # Errors
    /// * [`ContractError::AlreadyRegistered`] — if a record already exists for this hash
    pub fn register_document(
        env: Env,
        issuer: Address,
        owner: Address,
        document_hash: BytesN<32>,
    ) -> Result<DocumentRecord, ContractError> {
        issuer.require_auth();
        Self::check_rate_limit(&env, &issuer, &issuer)?;

        let key = DataKey::Document(document_hash.clone());

        if env.storage().persistent().has(&key) {
            return Err(ContractError::AlreadyRegistered);
        }

        let record = DocumentRecord {
            issuer: issuer.clone(),
            owner,
            timestamp: env.ledger().timestamp(),
            status: DocumentStatus::Active,
        };

        env.storage().persistent().set(&key, &record);
        DocumentRegistered {
            issuer,
            owner: record.owner.clone(),
            document_hash,
        }
        .publish(&env);

        Ok(record)
    }

    /// Retrieves a document record by its hash from persistent storage.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `document_hash` - 32-byte hash identifying the document
    ///
    /// # Returns
    /// `Some(DocumentRecord)` if found, `None` otherwise
    pub fn get_document(env: Env, document_hash: BytesN<32>) -> Option<DocumentRecord> {
        let key = DataKey::Document(document_hash);
        env.storage().persistent().get(&key)
    }

    /// Checks whether a document exists and is currently active.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `document_hash` - 32-byte hash identifying the document
    ///
    /// # Returns
    /// `true` only if the document exists and has `DocumentStatus::Active`
    pub fn verify_document(env: Env, document_hash: BytesN<32>) -> bool {
        let key = DataKey::Document(document_hash);
        env.storage()
            .persistent()
            .get::<DataKey, DocumentRecord>(&key)
            .map_or(false, |record| record.status == DocumentStatus::Active)
    }

    /// Returns the status of a document, or an error if it does not exist.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `document_hash` - 32-byte hash identifying the document
    ///
    /// # Errors
    /// * [`ContractError::DocumentNotFound`] — if no record exists for the given hash
    pub fn get_document_status(
        env: Env,
        document_hash: BytesN<32>,
    ) -> Result<DocumentStatus, ContractError> {
        let key = DataKey::Document(document_hash);
        env.storage()
            .persistent()
            .get::<DataKey, DocumentRecord>(&key)
            .map(|record| record.status)
            .ok_or(ContractError::DocumentNotFound)
    }

    /// Checks whether a document exists in storage, regardless of its status.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `document_hash` - 32-byte hash identifying the document
    ///
    /// # Returns
    /// `true` if any record (active or revoked) is stored under this hash
    pub fn document_exists(env: Env, document_hash: BytesN<32>) -> bool {
        let key = DataKey::Document(document_hash);
        env.storage().persistent().has(&key)
    }

    /// Revokes a previously registered document, preventing future verification.
    ///
    /// Only the original issuer of the document may revoke it. A document that has
    /// already been revoked cannot be revoked again.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `issuer`        - Address of the original issuer (must authorize)
    /// * `document_hash` - 32-byte hash identifying the document to revoke
    ///
    /// # Returns
    /// The updated [`DocumentRecord`] with `DocumentStatus::Revoked`
    ///
    /// # Errors
    /// * [`ContractError::DocumentNotFound`]    — if no record exists for this hash
    /// * [`ContractError::OnlyIssuerCanRevoke`] — if the caller is not the original issuer
    /// * [`ContractError::AlreadyRevoked`]      — if the document is already revoked
    pub fn revoke_document(
        env: Env,
        issuer: Address,
        document_hash: BytesN<32>,
    ) -> Result<DocumentRecord, ContractError> {
        issuer.require_auth();
        Self::check_rate_limit(&env, &issuer, &issuer)?;

        let key = DataKey::Document(document_hash.clone());

        let mut record: DocumentRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::DocumentNotFound)?;

        if record.issuer != issuer {
            return Err(ContractError::OnlyIssuerCanRevoke);
        }

        if record.status == DocumentStatus::Revoked {
            return Err(ContractError::AlreadyRevoked);
        }

        record.status = DocumentStatus::Revoked;

        env.storage().persistent().set(&key, &record);
        DocumentRevoked {
            issuer,
            document_hash,
        }
        .publish(&env);

        Ok(record)
    }

    /// Registers multiple documents in a single atomic transaction.
    ///
    /// The issuer authorizes once for the entire batch. All documents must be
    /// valid or the entire batch fails — no partial state is written.
    ///
    /// # Arguments
    /// * `env`       - The Soroban environment
    /// * `issuer`    - Address of the entity registering the documents (must authorize)
    /// * `documents` - Vector of [`DocumentInfo`] (owner + hash pairs), max 20 items
    ///
    /// # Returns
    /// A vector of newly created [`DocumentRecord`]s, all with `DocumentStatus::Active`
    ///
    /// # Errors
    /// * [`ContractError::BatchEmpty`]       — if the vector is empty
    /// * [`ContractError::BatchTooLarge`]    — if the vector exceeds 20 items
    /// * [`ContractError::AlreadyRegistered`] — if any document hash is already registered
    pub fn batch_register_documents(
        env: Env,
        issuer: Address,
        documents: Vec<DocumentInfo>,
    ) -> Result<Vec<DocumentRecord>, ContractError> {
        issuer.require_auth();
        Self::check_rate_limit(&env, &issuer, &issuer)?;

        if documents.is_empty() {
            return Err(ContractError::BatchEmpty);
        }
        if documents.len() > MAX_BATCH_SIZE {
            return Err(ContractError::BatchTooLarge);
        }

        let mut records = Vec::new(&env);

        for doc in documents.iter() {
            let key = DataKey::Document(doc.document_hash.clone());

            if env.storage().persistent().has(&key) {
                return Err(ContractError::AlreadyRegistered);
            }

            let record = DocumentRecord {
                issuer: issuer.clone(),
                owner: doc.owner.clone(),
                timestamp: env.ledger().timestamp(),
                status: DocumentStatus::Active,
            };

            env.storage().persistent().set(&key, &record);
            DocumentRegistered {
                issuer: issuer.clone(),
                owner: doc.owner.clone(),
                document_hash: doc.document_hash.clone(),
            }
            .publish(&env);

            records.push_back(record);
        }

        Ok(records)
    }

    /// Revokes multiple documents in a single atomic transaction.
    ///
    /// The issuer authorizes once for the entire batch. All documents must be
    /// revocable or the entire batch fails — no partial state is written.
    ///
    /// # Arguments
    /// * `env`            - The Soroban environment
    /// * `issuer`         - Address of the original issuer (must authorize)
    /// * `document_hashes` - Vector of 32-byte document hashes to revoke, max 20 items
    ///
    /// # Returns
    /// A vector of updated [`DocumentRecord`]s, all with `DocumentStatus::Revoked`
    ///
    /// # Errors
    /// * [`ContractError::BatchEmpty`]          — if the vector is empty
    /// * [`ContractError::BatchTooLarge`]       — if the vector exceeds 20 items
    /// * [`ContractError::DocumentNotFound`]    — if any hash has no record
    /// * [`ContractError::OnlyIssuerCanRevoke`] — if the caller is not the original issuer of any document
    /// * [`ContractError::AlreadyRevoked`]      — if any document is already revoked
    pub fn batch_revoke_documents(
        env: Env,
        issuer: Address,
        document_hashes: Vec<BytesN<32>>,
    ) -> Result<Vec<DocumentRecord>, ContractError> {
        issuer.require_auth();
        Self::check_rate_limit(&env, &issuer, &issuer)?;

        if document_hashes.is_empty() {
            return Err(ContractError::BatchEmpty);
        }
        if document_hashes.len() > MAX_BATCH_SIZE {
            return Err(ContractError::BatchTooLarge);
        }

        let mut records = Vec::new(&env);

        for document_hash in document_hashes.iter() {
            let key = DataKey::Document(document_hash.clone());

            let mut record: DocumentRecord = env
                .storage()
                .persistent()
                .get(&key)
                .ok_or(ContractError::DocumentNotFound)?;

            if record.issuer != issuer {
                return Err(ContractError::OnlyIssuerCanRevoke);
            }

            if record.status == DocumentStatus::Revoked {
                return Err(ContractError::AlreadyRevoked);
            }

            record.status = DocumentStatus::Revoked;
            env.storage().persistent().set(&key, &record);
            DocumentRevoked {
                issuer: issuer.clone(),
                document_hash: document_hash.clone(),
            }
            .publish(&env);

            records.push_back(record);
        }

        Ok(records)
    }

    /// Initializes the contract for a new deployment, setting the admin and contract version.
    ///
    /// Must be called once after deployment. Subsequent calls return `AlreadyInitialized`.
    ///
    /// # Arguments
    /// * `env`   - The Soroban environment
    /// * `admin` - Address that will govern future upgrades and migrations (must authorize)
    ///
    /// # Errors
    /// * [`ContractError::AlreadyInitialized`] — if the contract has already been initialized
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();

        if env.storage().persistent().has(&DataKey::Version) {
            return Err(ContractError::AlreadyInitialized);
        }

        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::Version, &CONTRACT_VERSION);

        ContractInitialized {
            admin,
            version: CONTRACT_VERSION,
        }
        .publish(&env);

        Ok(())
    }

    /// Returns the current contract version stored in ledger (0 if not initialized).
    pub fn get_version(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get::<DataKey, u32>(&DataKey::Version)
            .unwrap_or(0)
    }

    /// Returns the stored admin address, or `None` if the contract is not yet initialized.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage()
            .persistent()
            .get::<DataKey, Address>(&DataKey::Admin)
    }

    /// Upgrades the contract WASM to the given hash.
    ///
    /// The new WASM must already be uploaded to the Stellar ledger. After this call,
    /// subsequent invocations will execute the new WASM. Call `migrate` afterwards
    /// to apply any data transformations required by the new version.
    ///
    /// # Arguments
    /// * `env`          - The Soroban environment
    /// * `admin`        - The governance admin address (must authorize and match stored admin)
    /// * `new_wasm_hash` - 32-byte hash of the uploaded WASM binary
    ///
    /// # Errors
    /// * [`ContractError::NotInitialized`] — if the contract has not been initialized
    /// * [`ContractError::Unauthorized`]   — if the caller is not the stored admin
    pub fn upgrade(
        env: Env,
        admin: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), ContractError> {
        admin.require_auth();

        let stored_admin = env
            .storage()
            .persistent()
            .get::<DataKey, Address>(&DataKey::Admin)
            .ok_or(ContractError::NotInitialized)?;

        if stored_admin != admin {
            return Err(ContractError::Unauthorized);
        }

        let old_version = env
            .storage()
            .persistent()
            .get::<DataKey, u32>(&DataKey::Version)
            .unwrap_or(0);

        env.deployer().update_current_contract_wasm(new_wasm_hash);

        ContractUpgraded {
            admin,
            old_version,
            new_version: old_version,
        }
        .publish(&env);

        Ok(())
    }

    /// Migrates contract state to the current version.
    ///
    /// Detects the stored version and applies the appropriate data transformation:
    /// - Version 0 (pre-versioning): stores the admin and sets version to 1. This handles
    ///   existing deployments that were upgraded without a prior `initialize` call.
    /// - Version 1 (current): already up to date; returns `MigrationNotNeeded`.
    ///
    /// # Arguments
    /// * `env`   - The Soroban environment
    /// * `admin` - Must authorize; used as admin address when migrating from version 0
    ///
    /// # Returns
    /// The version number after migration
    ///
    /// # Errors
    /// * [`ContractError::Unauthorized`]     — if caller does not match stored admin (v1+)
    /// * [`ContractError::MigrationNotNeeded`] — if already at the latest version
    pub fn migrate(env: Env, admin: Address) -> Result<u32, ContractError> {
        admin.require_auth();

        let current_version = env
            .storage()
            .persistent()
            .get::<DataKey, u32>(&DataKey::Version)
            .unwrap_or(0);

        match current_version {
            0 => {
                // Pre-versioned state: bootstrap versioning without requiring prior initialize.
                // The admin arg becomes the stored admin for all future governance calls.
                env.storage().persistent().set(&DataKey::Admin, &admin);
                env.storage()
                    .persistent()
                    .set(&DataKey::Version, &CONTRACT_VERSION);
                Ok(CONTRACT_VERSION)
            }
            _ => Err(ContractError::MigrationNotNeeded),
        }
    }

    /// Sets a named feature flag.
    ///
    /// Feature flags allow toggling contract behaviours without a full WASM upgrade.
    ///
    /// # Arguments
    /// * `env`     - The Soroban environment
    /// * `admin`   - The governance admin address (must authorize and match stored admin)
    /// * `flag`    - The flag name as a `Symbol`
    /// * `enabled` - `true` to enable, `false` to disable
    ///
    /// # Errors
    /// * [`ContractError::NotInitialized`] — if the contract has not been initialized
    /// * [`ContractError::Unauthorized`]   — if the caller is not the stored admin
    pub fn set_feature_flag(
        env: Env,
        admin: Address,
        flag: Symbol,
        enabled: bool,
    ) -> Result<(), ContractError> {
        admin.require_auth();

        let stored_admin = env
            .storage()
            .persistent()
            .get::<DataKey, Address>(&DataKey::Admin)
            .ok_or(ContractError::NotInitialized)?;

        if stored_admin != admin {
            return Err(ContractError::Unauthorized);
        }

        env.storage()
            .persistent()
            .set(&DataKey::FeatureFlag(flag), &enabled);

        Ok(())
    }

    /// Returns the value of a named feature flag (`false` if not set).
    pub fn get_feature_flag(env: Env, flag: Symbol) -> bool {
        env.storage()
            .persistent()
            .get::<DataKey, bool>(&DataKey::FeatureFlag(flag))
            .unwrap_or(false)
    }

    /// Updates the rate-limit configuration for all contract operations.
    pub fn set_rate_limit_config(
        env: Env,
        admin: Address,
        config: RateLimitConfig,
    ) -> Result<(), ContractError> {
        admin.require_auth();

        let stored_admin = env
            .storage()
            .persistent()
            .get::<DataKey, Address>(&DataKey::Admin)
            .ok_or(ContractError::NotInitialized)?;

        if stored_admin != admin {
            return Err(ContractError::Unauthorized);
        }

        env.storage()
            .persistent()
            .set(&DataKey::RateLimitConfig, &config);
        Ok(())
    }

    /// Returns the current retry-after guidance for a scope, if one is pending.
    pub fn get_rate_limit_retry_after(env: Env, scope: RateLimitScope) -> Option<u64> {
        env.storage()
            .persistent()
            .get::<DataKey, u64>(&DataKey::RateLimitRetryAfter(scope))
    }

    fn check_rate_limit(env: &Env, caller: &Address, issuer: &Address) -> Result<(), ContractError> {
        let config = env
            .storage()
            .persistent()
            .get::<DataKey, RateLimitConfig>(&DataKey::RateLimitConfig)
            .unwrap_or_default();

        let now = env.ledger().timestamp();
        let address_scope = RateLimitScope::Address(caller.clone());
        let issuer_scope = RateLimitScope::Issuer(issuer.clone());

        for scope in [address_scope.clone(), issuer_scope.clone()] {
            let metrics = rate_limit_metrics();
            let (capacity, per_second) = match scope {
                RateLimitScope::Address(_) => (config.per_address_burst, config.per_address_per_second),
                RateLimitScope::Issuer(_) => (config.per_issuer_burst, config.per_issuer_per_second),
            };
            let mut state = env
                .storage()
                .persistent()
                .get::<DataKey, RateLimitBucketState>(&DataKey::RateLimitState(scope.clone()))
                .unwrap_or(RateLimitBucketState {
                    tokens: capacity,
                    last_refill: now,
                });

            let elapsed = now.saturating_sub(state.last_refill);
            let refill = elapsed.saturating_mul(per_second as u64);
            let tokens = state.tokens.saturating_add(refill as u32).min(capacity);
            let reset_detected = state.tokens == 0 && tokens > 0;

            if tokens == 0 {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    metrics.increment_rate_limit_violation();
                    metrics.increment_rate_limit_global_rejection("contract");
                }
                let retry_after = if per_second > 0 {
                    (1u64).saturating_div(per_second as u64).max(1)
                } else {
                    1u64
                };
                env.storage()
                    .persistent()
                    .set(&DataKey::RateLimitRetryAfter(scope), &retry_after);
                return Err(ContractError::RateLimitExceeded);
            }

            if reset_detected {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    metrics.increment_rate_limit_reset();
                }
            }

            state.tokens = tokens.saturating_sub(1);
            state.last_refill = now;
            #[cfg(not(target_arch = "wasm32"))]
            {
                metrics.record_token_consumed();
                metrics.increment_rate_limit_hit("contract");
            }
            env.storage().persistent().set(&DataKey::RateLimitState(scope.clone()), &state);
            env.storage().persistent().remove(&DataKey::RateLimitRetryAfter(scope));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (
        Env,
        ProofStellContractClient<'static>,
        Address,
        Address,
        BytesN<32>,
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ProofStellContract, ());
        let client = ProofStellContractClient::new(&env, &contract_id);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let document_hash = BytesN::from_array(&env, &[7; 32]);

        (env, client, issuer, owner, document_hash)
    }

    fn setup_with_config(
        env: &Env,
        client: &ProofStellContractClient<'static>,
        issuer: &Address,
        owner: &Address,
        config: RateLimitConfig,
    ) {
        let admin = Address::generate(env);
        client.initialize(&admin);
        client.set_rate_limit_config(&admin, &config);

        let _ = (issuer, owner);
    }

    #[test]
    fn rate_limit_allows_burst_then_blocks_excess() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ProofStellContract, ());
        let client = ProofStellContractClient::new(&env, &contract_id);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);

        let config = RateLimitConfig {
            per_address_per_second: 1,
            per_address_burst: 2,
            per_issuer_per_second: 1,
            per_issuer_burst: 2,
        };
        setup_with_config(&env, &client, &issuer, &owner, config);

        let hash1 = BytesN::from_array(&env, &[1; 32]);
        let hash2 = BytesN::from_array(&env, &[2; 32]);
        let hash3 = BytesN::from_array(&env, &[3; 32]);

        client.register_document(&issuer, &owner, &hash1);
        client.register_document(&issuer, &owner, &hash2);

        let err = client
            .try_register_document(&issuer, &owner, &hash3)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, ContractError::RateLimitExceeded);
    }

    #[test]
    fn rate_limit_refills_after_wait() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ProofStellContract, ());
        let client = ProofStellContractClient::new(&env, &contract_id);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);

        let config = RateLimitConfig {
            per_address_per_second: 1,
            per_address_burst: 1,
            per_issuer_per_second: 1,
            per_issuer_burst: 1,
        };
        setup_with_config(&env, &client, &issuer, &owner, config);

        let hash1 = BytesN::from_array(&env, &[10; 32]);
        let hash2 = BytesN::from_array(&env, &[11; 32]);
        client.register_document(&issuer, &owner, &hash1);

        let err = client
            .try_register_document(&issuer, &owner, &hash2)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, ContractError::RateLimitExceeded);

        let state = RateLimitBucketState {
            tokens: 1,
            last_refill: 0,
        };
        env.as_contract(&contract_id, || {
            env.storage().persistent().set(
                &DataKey::RateLimitState(RateLimitScope::Address(issuer.clone())),
                &state,
            );
            env.storage().persistent().set(
                &DataKey::RateLimitState(RateLimitScope::Issuer(issuer.clone())),
                &state,
            );
        });

        let hash3 = BytesN::from_array(&env, &[12; 32]);
        client.register_document(&issuer, &owner, &hash3);
    }

    #[test]
    fn rate_limit_is_scoped_per_address() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ProofStellContract, ());
        let client = ProofStellContractClient::new(&env, &contract_id);
        let issuer = Address::generate(&env);
        let other_issuer = Address::generate(&env);
        let owner = Address::generate(&env);

        let config = RateLimitConfig {
            per_address_per_second: 1,
            per_address_burst: 1,
            per_issuer_per_second: 10,
            per_issuer_burst: 10,
        };
        setup_with_config(&env, &client, &issuer, &owner, config);

        let hash1 = BytesN::from_array(&env, &[20; 32]);
        let hash2 = BytesN::from_array(&env, &[21; 32]);
        client.register_document(&issuer, &owner, &hash1);

        let err = client
            .try_register_document(&issuer, &owner, &hash2)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, ContractError::RateLimitExceeded);

        let hash3 = BytesN::from_array(&env, &[22; 32]);
        client.register_document(&other_issuer, &owner, &hash3);
    }

    #[test]
    fn registers_and_verifies_document() {
        let (_env, client, issuer, owner, document_hash) = setup();

        let record = client.register_document(&issuer, &owner, &document_hash);

        assert_eq!(record.issuer, issuer);
        assert_eq!(record.owner, owner);
        assert_eq!(record.status, DocumentStatus::Active);
        assert!(client.verify_document(&document_hash));
    }

    #[test]
    fn returns_document_record() {
        let (_env, client, issuer, owner, document_hash) = setup();

        let record = client.register_document(&issuer, &owner, &document_hash);

        assert_eq!(client.get_document(&document_hash), Some(record));
    }

    #[test]
    fn revokes_document() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        let record = client.revoke_document(&issuer, &document_hash);

        assert_eq!(record.status, DocumentStatus::Revoked);
        assert!(!client.verify_document(&document_hash));
    }

    #[test]
    fn prevents_duplicate_registration() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        let err = client
            .try_register_document(&issuer, &owner, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::AlreadyRegistered);
    }

    #[test]
    fn prevents_non_issuer_revocation() {
        let (env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);

        let other = Address::generate(&env);
        let err = client
            .try_revoke_document(&other, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::OnlyIssuerCanRevoke);
    }

    #[test]
    fn prevents_double_revocation() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        client.revoke_document(&issuer, &document_hash);

        let err = client
            .try_revoke_document(&issuer, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::AlreadyRevoked);
    }

    #[test]
    fn revoke_nonexistent_document_returns_not_found() {
        let (_env, client, issuer, _owner, document_hash) = setup();

        let err = client
            .try_revoke_document(&issuer, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::DocumentNotFound);
    }

    #[test]
    fn get_document_status_returns_not_found_for_missing_document() {
        let (_env, client, _issuer, _owner, document_hash) = setup();

        let err = client
            .try_get_document_status(&document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::DocumentNotFound);
    }

    #[test]
    fn get_document_status_returns_active_after_register() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        let status = client.get_document_status(&document_hash);

        assert_eq!(status, DocumentStatus::Active);
    }

    #[test]
    fn get_document_status_returns_revoked_after_revoke() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        client.revoke_document(&issuer, &document_hash);
        let status = client.get_document_status(&document_hash);

        assert_eq!(status, DocumentStatus::Revoked);
    }

    #[test]
    fn document_exists_returns_false_before_registration() {
        let (_env, client, _issuer, _owner, document_hash) = setup();

        assert!(!client.document_exists(&document_hash));
    }

    #[test]
    fn document_exists_returns_true_after_registration() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);

        assert!(client.document_exists(&document_hash));
    }

    // --- batch_register_documents ---

    #[test]
    fn batch_register_all_succeed() {
        let (env, client, issuer, owner, _) = setup();

        let docs = soroban_sdk::vec![
            &env,
            DocumentInfo {
                owner: owner.clone(),
                document_hash: BytesN::from_array(&env, &[1; 32])
            },
            DocumentInfo {
                owner: owner.clone(),
                document_hash: BytesN::from_array(&env, &[2; 32])
            },
            DocumentInfo {
                owner: owner.clone(),
                document_hash: BytesN::from_array(&env, &[3; 32])
            },
        ];

        let records = client.batch_register_documents(&issuer, &docs);

        assert_eq!(records.len(), 3);
        for record in records.iter() {
            assert_eq!(record.status, DocumentStatus::Active);
            assert_eq!(record.issuer, issuer);
        }
    }

    #[test]
    fn batch_register_fails_on_duplicate() {
        let (env, client, issuer, owner, _) = setup();

        let hash1 = BytesN::from_array(&env, &[1; 32]);
        let hash2 = BytesN::from_array(&env, &[2; 32]);
        client.register_document(&issuer, &owner, &hash1);

        let docs = soroban_sdk::vec![
            &env,
            DocumentInfo {
                owner: owner.clone(),
                document_hash: BytesN::from_array(&env, &[3; 32])
            },
            DocumentInfo {
                owner: owner.clone(),
                document_hash: hash1.clone()
            },
            DocumentInfo {
                owner: owner.clone(),
                document_hash: hash2.clone()
            },
        ];

        let err = client
            .try_batch_register_documents(&issuer, &docs)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::AlreadyRegistered);
        // hash2 must not have been stored (batch was atomic)
        assert!(!client.document_exists(&hash2));
    }

    #[test]
    fn batch_register_rejects_empty() {
        let (env, client, issuer, _, _) = setup();

        let docs: soroban_sdk::Vec<DocumentInfo> = soroban_sdk::vec![&env];
        let err = client
            .try_batch_register_documents(&issuer, &docs)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::BatchEmpty);
    }

    #[test]
    fn batch_register_rejects_oversized() {
        let (env, client, issuer, owner, _) = setup();

        let mut docs = soroban_sdk::vec![&env];
        for i in 0..21u8 {
            docs.push_back(DocumentInfo {
                owner: owner.clone(),
                document_hash: BytesN::from_array(&env, &[i; 32]),
            });
        }

        let err = client
            .try_batch_register_documents(&issuer, &docs)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::BatchTooLarge);
    }

    // --- batch_revoke_documents ---

    #[test]
    fn batch_revoke_all_succeed() {
        let (env, client, issuer, owner, _) = setup();

        let hashes = [
            BytesN::from_array(&env, &[1; 32]),
            BytesN::from_array(&env, &[2; 32]),
            BytesN::from_array(&env, &[3; 32]),
        ];
        for h in &hashes {
            client.register_document(&issuer, &owner, h);
        }

        let hash_vec = soroban_sdk::vec![
            &env,
            hashes[0].clone(),
            hashes[1].clone(),
            hashes[2].clone()
        ];
        let records = client.batch_revoke_documents(&issuer, &hash_vec);

        assert_eq!(records.len(), 3);
        for record in records.iter() {
            assert_eq!(record.status, DocumentStatus::Revoked);
        }
    }

    #[test]
    fn batch_revoke_fails_on_missing() {
        let (env, client, issuer, owner, _) = setup();

        let hash1 = BytesN::from_array(&env, &[1; 32]);
        let hash_missing = BytesN::from_array(&env, &[99; 32]);
        client.register_document(&issuer, &owner, &hash1);

        let hash_vec = soroban_sdk::vec![&env, hash1.clone(), hash_missing];
        let err = client
            .try_batch_revoke_documents(&issuer, &hash_vec)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::DocumentNotFound);
        // hash1 must still be Active (batch was atomic)
        assert_eq!(client.get_document_status(&hash1), DocumentStatus::Active);
    }

    #[test]
    fn batch_revoke_fails_on_wrong_issuer() {
        let (env, client, issuer, owner, _) = setup();

        let hash1 = BytesN::from_array(&env, &[1; 32]);
        let hash2 = BytesN::from_array(&env, &[2; 32]);
        client.register_document(&issuer, &owner, &hash1);
        client.register_document(&issuer, &owner, &hash2);

        let other = Address::generate(&env);
        let hash_vec = soroban_sdk::vec![&env, hash1.clone(), hash2.clone()];
        let err = client
            .try_batch_revoke_documents(&other, &hash_vec)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::OnlyIssuerCanRevoke);
        assert_eq!(client.get_document_status(&hash1), DocumentStatus::Active);
    }

    #[test]
    fn batch_revoke_fails_on_already_revoked() {
        let (env, client, issuer, owner, _) = setup();

        let hash1 = BytesN::from_array(&env, &[1; 32]);
        let hash2 = BytesN::from_array(&env, &[2; 32]);
        client.register_document(&issuer, &owner, &hash1);
        client.register_document(&issuer, &owner, &hash2);
        client.revoke_document(&issuer, &hash1);

        let hash_vec = soroban_sdk::vec![&env, hash1, hash2.clone()];
        let err = client
            .try_batch_revoke_documents(&issuer, &hash_vec)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::AlreadyRevoked);
        assert_eq!(client.get_document_status(&hash2), DocumentStatus::Active);
    }

    #[test]
    fn batch_revoke_rejects_empty() {
        let (_env, client, issuer, _, _) = setup();

        let hash_vec: soroban_sdk::Vec<BytesN<32>> = soroban_sdk::vec![&_env];
        let err = client
            .try_batch_revoke_documents(&issuer, &hash_vec)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::BatchEmpty);
    }

    #[test]
    fn batch_revoke_rejects_oversized() {
        let (env, client, issuer, owner, _) = setup();

        let mut hash_vec: soroban_sdk::Vec<BytesN<32>> = soroban_sdk::vec![&env];
        for i in 0..21u8 {
            let h = BytesN::from_array(&env, &[i; 32]);
            client.register_document(&issuer, &owner, &h);
            hash_vec.push_back(h);
        }

        let err = client
            .try_batch_revoke_documents(&issuer, &hash_vec)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::BatchTooLarge);
    }

    // --- initialize / get_version / get_admin ---

    #[test]
    fn initialize_sets_admin_and_version() {
        let (env, client, _, _, _) = setup();
        let admin = Address::generate(&env);

        client.initialize(&admin);

        assert_eq!(client.get_version(), 1);
        assert_eq!(client.get_admin(), Some(admin));
    }

    #[test]
    fn get_version_returns_zero_before_init() {
        let (_env, client, _, _, _) = setup();
        assert_eq!(client.get_version(), 0);
    }

    #[test]
    fn get_admin_returns_none_before_init() {
        let (_env, client, _, _, _) = setup();
        assert_eq!(client.get_admin(), None);
    }

    #[test]
    fn double_initialize_fails() {
        let (env, client, _, _, _) = setup();
        let admin = Address::generate(&env);

        client.initialize(&admin);

        let err = client.try_initialize(&admin).unwrap_err().unwrap();
        assert_eq!(err, ContractError::AlreadyInitialized);
    }

    // --- upgrade ---

    #[test]
    fn upgrade_requires_initialization() {
        let (env, client, _, _, _) = setup();
        let admin = Address::generate(&env);
        let wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

        let err = client.try_upgrade(&admin, &wasm_hash).unwrap_err().unwrap();
        assert_eq!(err, ContractError::NotInitialized);
    }

    #[test]
    fn non_admin_cannot_upgrade() {
        let (env, client, _, _, _) = setup();
        let admin = Address::generate(&env);
        let other = Address::generate(&env);
        let wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

        client.initialize(&admin);

        let err = client.try_upgrade(&other, &wasm_hash).unwrap_err().unwrap();
        assert_eq!(err, ContractError::Unauthorized);
    }

    // --- migrate ---

    #[test]
    fn migrate_v0_to_v1_sets_versioning() {
        let (env, client, _, _, _) = setup();
        let admin = Address::generate(&env);

        // Simulate pre-versioned state: no initialize called, DataKey::Version absent.
        let new_version = client.migrate(&admin);

        assert_eq!(new_version, 1);
        assert_eq!(client.get_version(), 1);
        assert_eq!(client.get_admin(), Some(admin));
    }

    #[test]
    fn migrate_already_current_fails() {
        let (env, client, _, _, _) = setup();
        let admin = Address::generate(&env);

        client.initialize(&admin);

        let err = client.try_migrate(&admin).unwrap_err().unwrap();
        assert_eq!(err, ContractError::MigrationNotNeeded);
    }

    #[test]
    fn documents_still_work_after_migration() {
        let (env, client, issuer, owner, document_hash) = setup();
        let admin = Address::generate(&env);

        // Register a document before any versioning is set up.
        client.register_document(&issuer, &owner, &document_hash);

        // Migrate from v0 to v1.
        client.migrate(&admin);

        // Document still verifiable after migration.
        assert!(client.verify_document(&document_hash));
        assert_eq!(
            client.get_document_status(&document_hash),
            DocumentStatus::Active
        );
    }

    // --- feature flags ---

    #[test]
    fn get_feature_flag_returns_false_for_unset() {
        let (env, client, _, _, _) = setup();
        let flag = Symbol::new(&env, "batch_ops");
        assert!(!client.get_feature_flag(&flag));
    }

    #[test]
    fn admin_can_set_and_get_feature_flag() {
        let (env, client, _, _, _) = setup();
        let admin = Address::generate(&env);
        let flag = Symbol::new(&env, "batch_ops");

        client.initialize(&admin);
        client.set_feature_flag(&admin, &flag, &true);

        assert!(client.get_feature_flag(&flag));
    }

    #[test]
    fn non_admin_cannot_set_feature_flag() {
        let (env, client, _, _, _) = setup();
        let admin = Address::generate(&env);
        let other = Address::generate(&env);
        let flag = Symbol::new(&env, "batch_ops");

        client.initialize(&admin);

        let err = client
            .try_set_feature_flag(&other, &flag, &true)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, ContractError::Unauthorized);
    }

    #[test]
    fn set_feature_flag_requires_initialization() {
        let (env, client, _, _, _) = setup();
        let admin = Address::generate(&env);
        let flag = Symbol::new(&env, "batch_ops");

        let err = client
            .try_set_feature_flag(&admin, &flag, &true)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, ContractError::NotInitialized);
    }
}
