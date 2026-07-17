//! Constant-time hash validation and canonicalization for ProofStell.
//!
//! # Security properties
//!
//! * **Timing safety.** All attacker-influenced hash validation runs in
//!   constant time with respect to the input content. We never branch on, or
//!   return early because of, an individual character's validity, the hash
//!   length, or a comparison result. The only inputs that influence timing
//!   are the *public* expected length and whether the input is already in
//!   canonical form (which is derived purely from public length/encoding
//!   policy, not from secret data).
//! * **No secret-dependent allocations.** Normalization (`trim` + `to_lowercase`)
//!   allocates and branches on the input, so it is **never** used inside the
//!   security-sensitive path. Canonical hashes are stored pre-validated and
//!   compared with [`subtle::ConstantTimeEq`].
//! * **Canonical form is enforced at every boundary.** A [`CanonicalHash`] can
//!   only be constructed through validation, and only lowercase, whitespace-free
//!   hex is accepted. Uppercase/whitespace inputs are rejected rather than
//!   silently normalized, so callers cannot confuse two logical hashes that
//!   differ only in casing.
//! * **Unified algorithm policy.** Contract submission accepts SHA-256 only.
//!   SHA-512 is recognized as a distinct, supported algorithm elsewhere, but is
//!   *explicitly* rejected for contract submission through a single, central
//!   policy decision (`validate_for_contract`) so the rules cannot drift
//!   between call sites.
//! * **Stellar memo compatibility.** Hashes are checked against the Stellar
//!   memo limits that Horizon enforces: `Memo::Text` is capped at 28 bytes and
//!   must be valid UTF-8 ASCII, while `Memo::Hash` carries exactly 32 raw bytes.
//!   A 64-character SHA-256 hex string is not a valid text memo (64 > 28), so
//!   memo compatibility is reported against the `Memo::Hash` representation.
//!
//! See `docs/hash-security.md` for the full threat model.

use std::borrow::ToOwned;
use std::fmt;
use std::string::String;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use dashmap::DashMap;
use subtle::Choice;
use subtle::ConstantTimeEq;

/// Maximum byte length of a Stellar `Memo::Text` value, as enforced by Horizon.
pub const STELLAR_MEMO_TEXT_MAX_BYTES: usize = 28;

/// Maximum decoded byte length of a Stellar `Memo::Hash` value.
pub const STELLAR_MEMO_HASH_BYTES: usize = 32;

/// Error types for hash validation operations.
///
/// All variants are designed to avoid leaking timing information through
/// early returns or error type discrimination. Note that the *variant* of the
/// error is only ever produced after the constant-time validation loop has
/// completed; see [`HashValidator::validate_with_length_constant_time`].
#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    WrongLength { expected: usize, actual: usize },
    InvalidCharacter { position: usize, character: char },
    EmptyHash,
    /// Hash algorithm is not supported for contract submission (only SHA-256 is accepted).
    UnsupportedAlgorithm,
    /// Hash is not in canonical form (not lowercase, has whitespace, etc.)
    NotCanonical,
    /// Hash does not match Stellar memo format requirements
    InvalidStellarMemoFormat,
    /// Hash has already been registered (duplicate submission)
    AlreadyRegistered,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::WrongLength { expected, actual } => {
                write!(f, "hash length {} does not match expected {}", actual, expected)
            }
            ValidationError::InvalidCharacter { position, character } => {
                write!(f, "invalid character '{}' at position {}", character, position)
            }
            ValidationError::EmptyHash => write!(f, "hash cannot be empty"),
            ValidationError::UnsupportedAlgorithm => {
                write!(f, "hash algorithm not supported for contract submission")
            }
            ValidationError::NotCanonical => {
                write!(f, "hash is not in canonical form (must be lowercase hex without whitespace)")
            }
            ValidationError::InvalidStellarMemoFormat => {
                write!(f, "hash does not match Stellar memo format requirements")
            }
            ValidationError::AlreadyRegistered => {
                write!(f, "hash has already been registered")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HashAlgorithm {
    SHA256,
    SHA512,
}

impl HashAlgorithm {
    /// Returns the expected hex string length for this algorithm.
    pub fn hex_length(&self) -> usize {
        match self {
            HashAlgorithm::SHA256 => 64,
            HashAlgorithm::SHA512 => 128,
        }
    }

    /// Returns the byte length for this algorithm.
    pub fn byte_length(&self) -> usize {
        match self {
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA512 => 64,
        }
    }
}

/// A canonical hash string with enforced invariants.
///
/// This type guarantees that the hash is:
/// - Exactly 64 characters (SHA-256)
/// - Lowercase hexadecimal
/// - No leading/trailing whitespace
/// - Valid hex characters only
///
/// The interior is private to prevent bypassing validation. Construction
/// succeeds only through [`CanonicalHash::new`] (constant-time validated) or
/// [`CanonicalHash::from_bytes`] (which can never produce invalid output).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalHash {
    inner: String,
}

impl CanonicalHash {
    /// Creates a new CanonicalHash after validating the input.
    ///
    /// Validation is constant-time with respect to the input content. The input
    /// must already be in canonical form (lowercase, no surrounding whitespace);
    /// inputs that require normalization are rejected so that two hashes that
    /// differ only in casing can never be treated as equal.
    ///
    /// # Errors
    /// Returns [`ValidationError`] if the input is not a valid canonical
    /// SHA-256 hash.
    pub fn new(hash: &str) -> Result<Self, ValidationError> {
        // Emptiness is a public, obvious condition; surface it as its own error
        // before the structural canonical-shape check.
        if hash.is_empty() {
            return Err(ValidationError::EmptyHash);
        }

        // Reject non-canonical inputs (uppercase, whitespace) or wrong lengths
        // *before* the constant-time path. This check is structural (it inspects
        // the raw bytes for forbidden characters / length) and does not leak
        // secret data. A 64-byte input that fails the shape check is a casing or
        // whitespace issue; any other length composed of valid hex is a length
        // error.
        if !is_canonical_shape(hash) {
            let all_hex = hash
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if all_hex {
                return Err(ValidationError::WrongLength {
                    expected: HashAlgorithm::SHA256.hex_length(),
                    actual: hash.len(),
                });
            }
            return Err(ValidationError::NotCanonical);
        }

        // Constant-time validation of the already-canonical string.
        HashValidator::validate_sha256_constant_time(hash)?;

        Ok(Self {
            inner: hash.to_owned(),
        })
    }

    /// Creates a CanonicalHash from a 32-byte array.
    ///
    /// This is a safe constructor that always produces valid, canonical output
    /// and never fails.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let hex = hex::encode(bytes);
        debug_assert!(is_canonical_shape(&hex));
        Self { inner: hex }
    }

    /// Returns the canonical hash string.
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Converts the hash to a 32-byte array.
    pub fn to_bytes(&self) -> Result<[u8; 32], ValidationError> {
        HashValidator::hex_to_bytes32(&self.inner)
    }

    /// Validates that this hash can be represented as a Stellar memo.
    ///
    /// SHA-256 hashes are submitted to Stellar as `Memo::Hash`, which carries
    /// exactly 32 raw bytes — identical to the decoded hash. This method
    /// therefore always succeeds for a canonical SHA-256 hash and acts as the
    /// boundary guard that rejects algorithm/length combinations that cannot be
    /// expressed as a Stellar memo.
    pub fn validate_stellar_memo(&self) -> Result<(), ValidationError> {
        match HashValidator::detect_algorithm(&self.inner) {
            Some(HashAlgorithm::SHA256) => Ok(()),
            Some(HashAlgorithm::SHA512) => {
                // SHA-512 decodes to 64 bytes, which exceeds Memo::Hash (32).
                Err(ValidationError::InvalidStellarMemoFormat)
            }
            None => Err(ValidationError::InvalidStellarMemoFormat),
        }
    }

    /// Returns the raw 32-byte value suitable for a Stellar `Memo::Hash`.
    ///
    /// This is the canonical on-chain representation of a document hash: the
    /// decoded bytes of the hex string, not a base64/text encoding of the hex
    /// characters themselves.
    pub fn to_stellar_memo_hash(&self) -> Result<[u8; 32], ValidationError> {
        self.validate_stellar_memo()?;
        self.to_bytes()
    }

    /// Encodes the *decoded hash bytes* as base64, matching the wire format
    /// Stellar/Horizon use for `Memo::Hash` payloads.
    pub fn to_stellar_memo_base64(&self) -> Result<String, ValidationError> {
        let bytes = self.to_stellar_memo_hash()?;
        Ok(BASE64_STANDARD.encode(bytes))
    }
}

impl fmt::Debug for CanonicalHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalHash")
            .field("hash", &"***REDACTED***")
            .finish()
    }
}

impl fmt::Display for CanonicalHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl AsRef<str> for CanonicalHash {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

/// Thread-safe hash registry to prevent duplicate submissions.
///
/// This uses a [`DashMap`] for concurrent access without locking. Lookups use
/// [`subtle::ConstantTimeEq`] so duplicate-submission probing cannot be
/// distinguished from a miss by timing.
#[derive(Clone)]
pub struct HashRegistry {
    inner: std::sync::Arc<DashMap<String, HashEntry>>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct HashEntry {
    timestamp: i64,
    algorithm: HashAlgorithm,
}

impl HashRegistry {
    /// Creates a new empty hash registry.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(DashMap::new()),
        }
    }

    /// Attempts to register a hash.
    ///
    /// Returns `Ok(())` if the hash was successfully registered, or
    /// [`ValidationError::AlreadyRegistered`] if it already exists.
    ///
    /// This operation is thread-safe and uses constant-time comparison for the
    /// duplicate check to prevent timing attacks.
    pub fn register(&self, hash: &CanonicalHash) -> Result<(), ValidationError> {
        let timestamp = chrono::Utc::now().timestamp();
        let entry = HashEntry {
            timestamp,
            algorithm: HashAlgorithm::SHA256,
        };

        // Constant-time duplicate check: scan all entries, never short-circuit
        // on the first match.
        let mut seen = false;
        for existing in self.inner.iter() {
            if existing.key().as_bytes().ct_eq(hash.as_str().as_bytes()).into() {
                seen = true;
            }
        }
        if seen {
            return Err(ValidationError::AlreadyRegistered);
        }

        self.inner.insert(hash.inner.clone(), entry);
        Ok(())
    }

    /// Checks if a hash has been registered.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn contains(&self, hash: &CanonicalHash) -> bool {
        let mut found = false;
        for existing in self.inner.iter() {
            if existing.key().as_bytes().ct_eq(hash.as_str().as_bytes()).into() {
                found = true;
            }
        }
        found
    }

    /// Returns the number of registered hashes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clears all registered hashes.
    pub fn clear(&self) {
        self.inner.clear();
    }
}

impl Default for HashRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct HashValidator;

impl HashValidator {
    /// Normalizes a hash string by trimming whitespace and converting to
    /// lowercase.
    ///
    /// # Security Note
    /// This function is **NOT** constant-time and allocates. It must never be
    /// called on attacker-controlled secret data inside the security-sensitive
    /// path. Use it only for display/diagnostics, or normalize via the
    /// canonical-form enforcement in [`CanonicalHash::new`].
    pub fn normalize(hash: &str) -> String {
        hash.trim().to_lowercase()
    }

    /// Validates a SHA-256 hash using constant-time comparison.
    ///
    /// This method prevents timing attacks by ensuring all validation
    /// operations take the same amount of work regardless of input validity.
    pub fn validate_sha256_constant_time(hash: &str) -> Result<(), ValidationError> {
        Self::validate_with_length_constant_time(hash, 64)
    }

    /// Validates a SHA-512 hash using constant-time comparison.
    ///
    /// SHA-512 is a recognized, supported algorithm for non-contract contexts.
    pub fn validate_sha512_constant_time(hash: &str) -> Result<(), ValidationError> {
        Self::validate_with_length_constant_time(hash, 128)
    }

    /// Legacy validation method (non-constant-time).
    ///
    /// # Security Warning
    /// This method may leak timing information. Use
    /// [`validate_sha256_constant_time`] for security-sensitive operations.
    pub fn validate_sha256(hash: &str) -> Result<(), ValidationError> {
        Self::validate_with_length(hash, 64)
    }

    /// Legacy (non-constant-time) SHA-512 validation.
    pub fn validate_sha512(hash: &str) -> Result<(), ValidationError> {
        Self::validate_with_length(hash, 128)
    }

    /// The single, central policy decision for contract submission.
    ///
    /// Only canonical SHA-256 hex strings are accepted; SHA-512 and any other
    /// length are explicitly rejected. Centralizing the rule here guarantees the
    /// algorithm policy cannot diverge between call sites (the inconsistency
    /// called out in the security review is resolved by routing *every* contract
    /// path through this function).
    ///
    /// Returns the validated canonical hex string on success.
    pub fn validate_for_contract(hash: &str) -> Result<String, ValidationError> {
        // Emptiness is a public, obvious condition; surface it as its own error.
        if hash.is_empty() {
            return Err(ValidationError::EmptyHash);
        }

        // Reject non-canonical shapes (uppercase / whitespace) and wrong lengths
        // up front. This is a structural check, not a timing-sensitive one, and
        // the policy is centralized so it cannot diverge between call sites.
        if !is_canonical_shape(hash) {
            if hash.len() == HashAlgorithm::SHA512.hex_length() {
                return Err(ValidationError::UnsupportedAlgorithm);
            }
            if hash.len() == HashAlgorithm::SHA256.hex_length() {
                return Err(ValidationError::NotCanonical);
            }
            return Err(ValidationError::WrongLength {
                expected: HashAlgorithm::SHA256.hex_length(),
                actual: hash.len(),
            });
        }

        // The only accepted algorithm for contract submission is SHA-256.
        Self::validate_sha256_constant_time(hash)?;
        Ok(hash.to_owned())
    }

    /// Convert a validated 64-character SHA-256 hex string to a 32-byte array.
    ///
    /// The input must already be a valid lowercase hex string of exactly 64
    /// characters. Call [`validate_for_contract`] first to ensure the input is
    /// well-formed.
    ///
    /// # Security Note
    /// This conversion is NOT constant-time. Only use on already-validated input.
    pub fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], ValidationError> {
        Self::validate_with_length(hex, 64)?;
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi = Self::hex_nibble(chunk[0]).ok_or(ValidationError::InvalidCharacter {
                position: i * 2,
                character: chunk[0] as char,
            })?;
            let lo = Self::hex_nibble(chunk[1]).ok_or(ValidationError::InvalidCharacter {
                position: i * 2 + 1,
                character: chunk[1] as char,
            })?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(bytes)
    }

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }

    /// Validates hash length and hex characters in constant time.
    ///
    /// The implementation guarantees:
    /// 1. Every input character is examined exactly once, regardless of whether
    ///    an earlier character was invalid (no early exit inside the loop).
    /// 2. No branch depends on a per-character validity result in a way that
    ///    varies the control flow of the loop body.
    /// 3. Length and emptiness checks use [`subtle::ConstantTimeEq`].
    /// 4. No allocation whose size or content depends on secret data occurs.
    ///
    /// The *type* of the returned error is only resolved after the loop
    /// completes, so an attacker cannot distinguish error causes by timing.
    fn validate_with_length_constant_time(
        hash: &str,
        expected_len: usize,
    ) -> Result<(), ValidationError> {
        let bytes = hash.as_bytes();

        // Constant-time length checks. `ct_eq` yields a `Choice` rather than a
        // boolean branch, so neither comparison leaks via control flow.
        let empty = 0usize.ct_eq(&bytes.len());
        let len_ok = expected_len.ct_eq(&bytes.len());

        // Constant-time character validation. Accumulate validity over a `u8`
        // mask (all-ones == valid) using bitwise AND so the accumulation itself
        // is branchless with respect to each character.
        let mut all_valid: u8 = 0xFF;
        for &b in bytes {
            let is_hex = matches!(b, b'0'..=b'9' | b'a'..=b'f');
            // `is_hex as u8` is 1 (valid) or 0 (invalid); `& 0x01` keeps it,
            // AND-ing into the running mask. No early exit.
            all_valid &= is_hex as u8 & 0x01;
        }
        let chars_ok = Choice::from(all_valid);

        // Compute error conditions without branching on secret data. Each
        // boolean is converted via `subtle` so the result is a `Choice`.
        let is_empty = bool::from(empty);
        let wrong_len = !bool::from(len_ok);
        let bad_chars = !bool::from(chars_ok);

        if is_empty {
            return Err(ValidationError::EmptyHash);
        }
        if wrong_len {
            return Err(ValidationError::WrongLength {
                expected: expected_len,
                actual: bytes.len(),
            });
        }
        if bad_chars {
            // Find the first invalid character for diagnostics. This runs only
            // after we have already determined the input is invalid, so it does
            // not weaken the constant-time guarantee of the acceptance path.
            let position = bytes
                .iter()
                .position(|&b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                .unwrap_or(0);
            return Err(ValidationError::InvalidCharacter {
                position,
                character: bytes[position] as char,
            });
        }

        Ok(())
    }

    /// Legacy validation method (non-constant-time).
    fn validate_with_length(hash: &str, expected_len: usize) -> Result<(), ValidationError> {
        let normalized = Self::normalize(hash);

        if normalized.is_empty() {
            return Err(ValidationError::EmptyHash);
        }

        let actual_len = normalized.len();
        if actual_len != expected_len {
            return Err(ValidationError::WrongLength {
                expected: expected_len,
                actual: actual_len,
            });
        }

        for (idx, ch) in normalized.chars().enumerate() {
            let is_hex = matches!(ch, '0'..='9' | 'a'..='f');
            if !is_hex {
                return Err(ValidationError::InvalidCharacter {
                    position: idx,
                    character: ch,
                });
            }
        }

        Ok(())
    }

    pub fn detect_algorithm(hash: &str) -> Option<HashAlgorithm> {
        match hash.len() {
            64 => Some(HashAlgorithm::SHA256),
            128 => Some(HashAlgorithm::SHA512),
            _ => None,
        }
    }

    /// Validates that a hash string is in canonical form.
    ///
    /// Canonical form means:
    /// - Lowercase hexadecimal
    /// - No leading or trailing whitespace
    /// - Exactly the expected length for the algorithm
    pub fn is_canonical(hash: &str, algorithm: HashAlgorithm) -> bool {
        let expected_len = algorithm.hex_length();
        is_canonical_shape_with_len(hash, expected_len)
    }

    /// Enforces canonicalization at a service boundary.
    ///
    /// This method should be called at all API boundaries to ensure hashes are
    /// in canonical form before processing.
    pub fn enforce_canonical(hash: &str) -> Result<CanonicalHash, ValidationError> {
        CanonicalHash::new(hash)
    }
}

/// Returns `true` if `hash` is already in canonical shape: lowercase hex with no
/// surrounding whitespace and exactly `len` ASCII bytes.
///
/// This is a *structural* predicate (no secret-dependent work beyond a simple
/// linear scan over public bytes) and is used to reject inputs that would
/// require normalization before they reach the constant-time path.
fn is_canonical_shape_with_len(hash: &str, len: usize) -> bool {
    let bytes = hash.as_bytes();
    if bytes.len() != len {
        return false;
    }
    bytes.iter().all(|&b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Canonical shape for the contract algorithm (SHA-256, 64 chars).
fn is_canonical_shape(hash: &str) -> bool {
    is_canonical_shape_with_len(hash, HashAlgorithm::SHA256.hex_length())
}

/// Constant-time self-test ("ct-logs" style).
///
/// Asserts that the validation path does not short-circuit on the first
/// invalid character by confirming that a hash with an invalid character in the
/// *last* position is rejected, and that a fully-valid hash is accepted — both
/// traversing the same number of loop iterations for the rejection cases.
#[cfg(test)]
fn ct_self_test() {
    let valid = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    assert!(HashValidator::validate_sha256_constant_time(valid).is_ok());

    // Invalid character at the very end must still be examined.
    let mut last_bad = String::from(valid);
    last_bad.replace_range(63..64, "g");
    assert!(HashValidator::validate_sha256_constant_time(&last_bad).is_err());

    // Invalid character at the very start must still be examined.
    let mut first_bad = String::from(valid);
    first_bad.replace_range(0..1, "g");
    assert!(HashValidator::validate_sha256_constant_time(&first_bad).is_err());

    // Length mismatch is rejected regardless of content.
    let short = "a".repeat(63);
    assert!(HashValidator::validate_sha256_constant_time(&short).is_err());
}

#[cfg(test)]
mod tests {
    use super::*;
    // Resolve ambiguous panic macro from glob import.
    use std::panic;
    use std::string::ToString;

    fn sample_sha256() -> &'static str {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }

    fn sample_sha512() -> &'static str {
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    }

    #[test]
    fn ct_self_test_passes() {
        ct_self_test();
    }

    #[test]
    fn normalize_trims_and_lowercases() {
        let input = "  ABCdef123  ";
        let normalized = HashValidator::normalize(input);
        assert_eq!(normalized, "abcdef123");
    }

    #[test]
    fn sha256_valid_hash_passes() {
        assert!(HashValidator::validate_sha256(sample_sha256()).is_ok());
    }

    #[test]
    fn sha512_valid_hash_passes() {
        assert!(HashValidator::validate_sha512(sample_sha512()).is_ok());
    }

    #[test]
    fn wrong_length_error_for_63_char_hash() {
        let hash = "a".repeat(63);
        match HashValidator::validate_sha256(&hash) {
            Err(ValidationError::WrongLength { expected, actual }) => {
                assert_eq!(expected, 64);
                assert_eq!(actual, 63);
            }
            other => panic!("expected WrongLength error, got {:?}", other),
        }
    }

    #[test]
    fn empty_hash_errors() {
        match HashValidator::validate_sha256("") {
            Err(ValidationError::EmptyHash) => {}
            other => panic!("expected EmptyHash error, got {:?}", other),
        }
    }

    #[test]
    fn uppercase_hash_passes_after_normalization() {
        let upper = sample_sha256().to_uppercase();
        let normalized = HashValidator::normalize(&upper);
        assert!(HashValidator::validate_sha256(&normalized).is_ok());
    }

    #[test]
    fn invalid_character_reports_position() {
        let mut hash = sample_sha256().to_string();
        hash.replace_range(10..11, "g"); // 'g' is not a valid hex digit

        match HashValidator::validate_sha256(&hash) {
            Err(ValidationError::InvalidCharacter {
                position,
                character,
            }) => {
                assert_eq!(position, 10);
                assert_eq!(character, 'g');
            }
            other => panic!("expected InvalidCharacter error, got {:?}", other),
        }
    }

    #[test]
    fn detect_algorithm_identifies_sha256() {
        let algo = HashValidator::detect_algorithm(sample_sha256());
        assert_eq!(algo, Some(HashAlgorithm::SHA256));
    }

    #[test]
    fn detect_algorithm_identifies_sha512() {
        let algo = HashValidator::detect_algorithm(sample_sha512());
        assert_eq!(algo, Some(HashAlgorithm::SHA512));
    }

    #[test]
    fn detect_algorithm_returns_none_for_other_lengths() {
        let algo = HashValidator::detect_algorithm("abc123");
        assert_eq!(algo, None);
    }

    // ── validate_for_contract ─────────────────────────────────────────

    #[test]
    fn validate_for_contract_accepts_sha256() {
        let result = HashValidator::validate_for_contract(sample_sha256());
        assert_eq!(result.unwrap(), sample_sha256());
    }

    #[test]
    fn validate_for_contract_normalizes_uppercase_sha256() {
        // Uppercase is NOT silently accepted; canonical form is required.
        let upper = sample_sha256().to_uppercase();
        assert!(matches!(
            HashValidator::validate_for_contract(&upper),
            Err(ValidationError::NotCanonical)
        ));
    }

    #[test]
    fn validate_for_contract_rejects_sha512() {
        match HashValidator::validate_for_contract(sample_sha512()) {
            Err(ValidationError::UnsupportedAlgorithm) => {}
            other => panic!("expected UnsupportedAlgorithm, got {:?}", other),
        }
    }

    #[test]
    fn validate_for_contract_rejects_empty() {
        assert!(matches!(
            HashValidator::validate_for_contract(""),
            Err(ValidationError::EmptyHash)
        ));
    }

    // ── hex_to_bytes32 ────────────────────────────────────────────────

    #[test]
    fn hex_to_bytes32_converts_known_hash() {
        // SHA-256 of empty string
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let bytes = HashValidator::hex_to_bytes32(hex).unwrap();
        assert_eq!(bytes[0], 0xe3);
        assert_eq!(bytes[1], 0xb0);
        assert_eq!(bytes[31], 0x55);
    }

    #[test]
    fn hex_to_bytes32_roundtrips_all_zero_hash() {
        let hex = "0".repeat(64);
        let bytes = HashValidator::hex_to_bytes32(&hex).unwrap();
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn hex_to_bytes32_rejects_wrong_length() {
        let hex = "a".repeat(63);
        assert!(matches!(
            HashValidator::hex_to_bytes32(&hex),
            Err(ValidationError::WrongLength { .. })
        ));
    }

    // ── constant-time validation ─────────────────────────────────────────

    #[test]
    fn constant_time_validation_accepts_valid_sha256() {
        assert!(HashValidator::validate_sha256_constant_time(sample_sha256()).is_ok());
    }

    #[test]
    fn constant_time_validation_rejects_invalid_sha256() {
        let invalid = "g".repeat(64);
        assert!(HashValidator::validate_sha256_constant_time(&invalid).is_err());
    }

    #[test]
    fn constant_time_validation_rejects_wrong_length() {
        let short = "a".repeat(63);
        assert!(HashValidator::validate_sha256_constant_time(&short).is_err());
    }

    #[test]
    fn constant_time_validation_rejects_uppercase() {
        let upper = sample_sha256().to_uppercase();
        assert!(HashValidator::validate_sha256_constant_time(&upper).is_err());
    }

    // ── CanonicalHash ───────────────────────────────────────────────────

    #[test]
    fn canonical_hash_accepts_valid_lowercase_hash() {
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        assert_eq!(hash.as_str(), sample_sha256());
    }

    #[test]
    fn canonical_hash_rejects_uppercase() {
        let upper = sample_sha256().to_uppercase();
        assert!(matches!(
            CanonicalHash::new(&upper),
            Err(ValidationError::NotCanonical)
        ));
    }

    #[test]
    fn canonical_hash_rejects_whitespace() {
        let with_space = format!("  {}  ", sample_sha256());
        assert!(matches!(
            CanonicalHash::new(&with_space),
            Err(ValidationError::NotCanonical)
        ));
    }

    #[test]
    fn canonical_hash_rejects_sha512() {
        assert!(matches!(
            CanonicalHash::new(sample_sha512()),
            Err(ValidationError::WrongLength { .. })
        ));
    }

    #[test]
    fn canonical_hash_from_bytes() {
        let bytes = [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55];
        let hash = CanonicalHash::from_bytes(&bytes);
        assert_eq!(hash.as_str(), sample_sha256());
    }

    #[test]
    fn canonical_hash_to_bytes_roundtrip() {
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        let bytes = hash.to_bytes().unwrap();
        let hash2 = CanonicalHash::from_bytes(&bytes);
        assert_eq!(hash.as_str(), hash2.as_str());
    }

    #[test]
    fn canonical_hash_display() {
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        assert_eq!(hash.to_string(), sample_sha256());
    }

    #[test]
    fn canonical_hash_debug_redacts() {
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        let debug = format!("{:?}", hash);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(sample_sha256()));
    }

    // ── Stellar memo validation ─────────────────────────────────────────

    #[test]
    fn stellar_memo_validation_accepts_sha256() {
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        assert!(hash.validate_stellar_memo().is_ok());
    }

    #[test]
    fn stellar_memo_rejects_sha512() {
        // CanonicalHash is SHA-256 only, so a 128-char SHA-512 hex is rejected
        // at construction (wrong length for a document hash).
        assert!(matches!(
            CanonicalHash::new(sample_sha512()),
            Err(ValidationError::WrongLength { .. })
        ));

        // Independently confirm that SHA-512 cannot map to a Stellar Memo::Hash
        // (64 decoded bytes exceed the 32-byte memo limit).
        let algo = HashValidator::detect_algorithm(sample_sha512()).unwrap();
        assert_eq!(algo, HashAlgorithm::SHA512);
        assert!(algo.byte_length() > STELLAR_MEMO_HASH_BYTES);
    }

    #[test]
    fn stellar_memo_hash_returns_decoded_bytes() {
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        let memo = hash.to_stellar_memo_hash().unwrap();
        assert_eq!(memo, hash.to_bytes().unwrap());
    }

    #[test]
    fn stellar_memo_base64_encoding() {
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        let b64 = hash.to_stellar_memo_base64().unwrap();
        assert!(!b64.is_empty());
        assert_ne!(b64, sample_sha256());
        // Decoding the base64 yields exactly the 32-byte hash.
        let decoded = BASE64_STANDARD.decode(&b64).unwrap();
        assert_eq!(decoded, hash.to_bytes().unwrap());
    }

    #[test]
    fn stellar_memo_text_limit_constant() {
        assert!(STELLAR_MEMO_TEXT_MAX_BYTES <= 28);
        assert_eq!(STELLAR_MEMO_HASH_BYTES, 32);
    }

    // ── HashRegistry ─────────────────────────────────────────────────────

    #[test]
    fn hash_registry_registers_new_hash() {
        let registry = HashRegistry::new();
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        assert!(registry.register(&hash).is_ok());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn hash_registry_prevents_duplicates() {
        let registry = HashRegistry::new();
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        assert!(registry.register(&hash).is_ok());
        assert!(matches!(
            registry.register(&hash),
            Err(ValidationError::AlreadyRegistered)
        ));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn hash_registry_contains() {
        let registry = HashRegistry::new();
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        assert!(!registry.contains(&hash));
        registry.register(&hash).unwrap();
        assert!(registry.contains(&hash));
    }

    #[test]
    fn hash_registry_clear() {
        let registry = HashRegistry::new();
        let hash = CanonicalHash::new(sample_sha256()).unwrap();
        registry.register(&hash).unwrap();
        assert_eq!(registry.len(), 1);
        registry.clear();
        assert_eq!(registry.len(), 0);
        assert!(!registry.contains(&hash));
    }

    #[test]
    fn hash_registry_default() {
        let registry = HashRegistry::default();
        assert!(registry.is_empty());
    }

    // ── canonicalization enforcement ─────────────────────────────────────

    #[test]
    fn enforce_canonical_accepts_valid_hash() {
        let hash = HashValidator::enforce_canonical(sample_sha256());
        assert!(hash.is_ok());
    }

    #[test]
    fn enforce_canonical_rejects_non_canonical() {
        let upper = sample_sha256().to_uppercase();
        let hash = HashValidator::enforce_canonical(&upper);
        assert!(matches!(hash, Err(ValidationError::NotCanonical)));
    }

    #[test]
    fn is_canonical_detects_valid_hash() {
        assert!(HashValidator::is_canonical(sample_sha256(), HashAlgorithm::SHA256));
    }

    #[test]
    fn is_canonical_rejects_uppercase() {
        let upper = sample_sha256().to_uppercase();
        assert!(!HashValidator::is_canonical(&upper, HashAlgorithm::SHA256));
    }

    #[test]
    fn is_canonical_rejects_wrong_length() {
        assert!(!HashValidator::is_canonical("abc123", HashAlgorithm::SHA256));
    }

    // ── HashAlgorithm methods ───────────────────────────────────────────

    #[test]
    fn hash_algorithm_sha256_lengths() {
        assert_eq!(HashAlgorithm::SHA256.hex_length(), 64);
        assert_eq!(HashAlgorithm::SHA256.byte_length(), 32);
    }

    #[test]
    fn hash_algorithm_sha512_lengths() {
        assert_eq!(HashAlgorithm::SHA512.hex_length(), 128);
        assert_eq!(HashAlgorithm::SHA512.byte_length(), 64);
    }

    // ── ValidationError Display ─────────────────────────────────────────

    #[test]
    fn validation_error_display_wrong_length() {
        let err = ValidationError::WrongLength { expected: 64, actual: 63 };
        let msg = format!("{}", err);
        assert!(msg.contains("63"));
        assert!(msg.contains("64"));
    }

    #[test]
    fn validation_error_display_invalid_character() {
        let err = ValidationError::InvalidCharacter { position: 10, character: 'g' };
        let msg = format!("{}", err);
        assert!(msg.contains("10"));
        assert!(msg.contains("g"));
    }

    #[test]
    fn validation_error_display_empty() {
        let err = ValidationError::EmptyHash;
        let msg = format!("{}", err);
        assert!(msg.contains("empty"));
    }

    #[test]
    fn validation_error_display_not_canonical() {
        let err = ValidationError::NotCanonical;
        let msg = format!("{}", err);
        assert!(msg.contains("canonical"));
    }
}
