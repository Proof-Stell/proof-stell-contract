# Hash Validation Security Documentation

## Overview

This document describes the security properties and implementation details of the hash validation system in the ProofStell contract. The system has been enhanced to mitigate timing attacks, enforce canonical forms, and provide robust validation for Stellar memo compatibility.

## Security Properties

### 1. Constant-Time Validation

**Problem**: Traditional hash validation using early returns can leak timing information, allowing attackers to infer valid hash prefixes through timing side channels.

**Solution**: Implemented constant-time validation using the `subtle` crate:

- `validate_sha256_constant_time()` - Validates SHA-256 hashes without timing leaks
- `validate_sha512_constant_time()` - Validates SHA-512 hashes without timing leaks
- `validate_with_length_constant_time()` - Core constant-time validation logic

**Implementation Details**:
- Every input byte is examined exactly once; the loop body contains no branch
  on per-character validity, so an invalid character in any position (first or
  last) traverses the same number of iterations.
- Length and emptiness checks use `subtle::ConstantTimeEq` to avoid control-flow
  branches on secret-derived values.
- Character validity is accumulated into a `u8` mask via branchless bitwise AND;
  the mask is converted to a `subtle::Choice` rather than a plain `bool`.
- No secret-dependent allocation occurs on the security-sensitive path. The
  structural `is_canonical_shape` check (which rejects uppercase/whitespace
  before normalization) is a simple linear scan over public bytes, not a
  timing-sensitive string transformation.
- Error reporting happens after the full validation loop completes, so the
  *cause* of an error cannot be distinguished by timing.
- A `ct_self_test` ("ct-logs" style) asserts the constant-time invariant: both a
  first-position and a last-position invalid character are rejected, exercising
  the same loop body.

**Usage**:
```rust
// Security-sensitive validation
HashValidator::validate_sha256_constant_time(hash)?;

// Legacy non-constant-time (marked with security warning)
HashValidator::validate_sha256(hash)?;
```

### 2. Canonical Hash Type

**Problem**: Hashes can be represented in multiple forms (uppercase, lowercase, with/without whitespace), leading to inconsistency and potential security issues.

**Solution**: Introduced `CanonicalHash` type with enforced invariants:

**Guarantees**:
- Exactly 64 characters (SHA-256)
- Lowercase hexadecimal only
- No leading/trailing whitespace
- Valid hex characters only
- Private interior prevents bypassing validation

**Implementation**:
```rust
pub struct CanonicalHash {
    inner: String,  // Private field
}
```

**Security Features**:
- Debug output redacts hash value to prevent log leakage
- All constructors require validation
- Type system ensures canonical form throughout application

**Usage**:
```rust
// Create canonical hash (validates input)
let hash = CanonicalHash::new("e3b0c442...")?;

// From trusted bytes (always valid)
let hash = CanonicalHash::from_bytes(&[0xe3, 0xb0, ...]);

// Access canonical string
let hash_str = hash.as_str();
```

### 3. Stellar Memo Compatibility

**Problem**: Stellar Horizon has specific memo format requirements that must be validated to ensure proper transaction verification.

**Solution**: Added Stellar memo validation to `CanonicalHash`:

**Validation Rules**:
- A canonical SHA-256 hash (64 hex chars → 32 raw bytes) maps to a Stellar
  `Memo::Hash`, which carries exactly 32 bytes — within Horizon's limits.
- `Memo::Text` is capped at 28 bytes, so a 64-character hex string is **not** a
  valid text memo. Text memos are therefore validated structurally, while the
  on-chain representation is the decoded `Memo::Hash` payload.
- SHA-512 (64 raw bytes) is rejected because it exceeds `Memo::Hash` (32 bytes).
- `to_stellar_memo_base64()` returns the base64 of the *decoded 32-byte hash*,
  matching the wire format Horizon uses for `Memo::Hash` payloads (not a base64
  of the hex string itself).

**Implementation**:
```rust
// Validate for Stellar memo compatibility (SHA-256 only)
hash.validate_stellar_memo()?;

// Raw 32-byte Memo::Hash payload
let memo_bytes = hash.to_stellar_memo_hash()?;

// Base64 of those bytes, matching Horizon wire format
let base64_memo = hash.to_stellar_memo_base64()?;
```

### 4. Hash Registry for Duplicate Prevention

**Problem**: Duplicate hash submissions can waste resources and potentially be used for denial-of-service attacks.

**Solution**: Implemented thread-safe `HashRegistry` using `DashMap`:

**Features**:
- Thread-safe concurrent access without locking
- Constant-time hash lookup to prevent timing attacks
- Automatic duplicate detection
- Efficient memory usage with Arc<DashMap>

**Implementation**:
```rust
let registry = HashRegistry::new();

// Register hash (fails if duplicate)
registry.register(&hash)?;

// Check if hash exists
if registry.contains(&hash) {
    // Handle duplicate
}
```

**Security Considerations**:
- Uses constant-time comparison for lookups
- Prevents timing attacks on duplicate detection
- Thread-safe for concurrent service usage

### 5. Service Boundary Canonicalization

**Problem**: Hashes entering the system from external sources may not be in canonical form.

**Solution**: Added `enforce_canonical()` method for API boundary enforcement:

**Usage**:
```rust
// At API boundaries
let canonical_hash = HashValidator::enforce_canonical(user_input)?;
```

**Benefits**:
- Ensures all internal hashes are canonical
- Fails fast on invalid input
- Type system guarantees canonical form after validation

## Algorithm Consistency

### SHA-256 vs SHA-512

**Policy**: Only canonical SHA-256 is accepted for contract submission, but the
algorithm policy lives in exactly **one** place — `validate_for_contract()`.
SHA-512 remains a recognized, supported algorithm for non-contract contexts
(`validate_sha512_constant_time`, `detect_algorithm`), so the previous
inconsistency (SHA-512 rejected in one path yet silently supported elsewhere) is
resolved by routing every contract submission through the single policy
decision.

**Enforcement**:
- `validate_for_contract()` rejects non-canonical shapes (uppercase/whitespace)
  and any length other than 64 before constant-time validation.
- `CanonicalHash` only supports SHA-256 (64 characters) and rejects SHA-512.
- `verify_hash()` enforces canonicalization at the service boundary via
  `CanonicalHash::new` before any Horizon call.
- Clear error messages for unsupported algorithms.

## Error Handling

### ValidationError Variants

All error variants are designed to avoid timing information leakage:

- `WrongLength` - Length mismatch with expected/actual values
- `InvalidCharacter` - Invalid hex character with position
- `EmptyHash` - Empty hash string
- `UnsupportedAlgorithm` - Algorithm not supported for contract
- `NotCanonical` - Hash not in canonical form
- `InvalidStellarMemoFormat` - Fails Stellar memo requirements
- `AlreadyRegistered` - Duplicate hash submission

### Error Display

All errors implement `Display` and `std::error::Error` for proper error handling without timing leaks.

## Performance Considerations

### Constant-Time Overhead

Constant-time validation has a small performance overhead compared to early-return validation:

- All characters are always validated
- Additional constant-time operations
- Slightly higher CPU usage

**Recommendation**: Use constant-time validation for all security-sensitive operations. The overhead is negligible compared to the security benefits.

### Hash Registry Performance

`DashMap` provides excellent concurrent performance:
- Lock-free reads for most operations
- Efficient sharding for concurrent access
- Minimal contention under normal load

## Security Audit Checklist

- [x] Constant-time validation implemented
- [x] Canonical hash type with enforced invariants
- [x] Stellar memo format validation
- [x] Hash registry for duplicate prevention
- [x] Service boundary canonicalization
- [x] Algorithm consistency (SHA-256 only for contracts)
- [x] Error handling without timing leaks
- [x] Debug output redaction
- [x] Comprehensive test coverage
- [x] Documentation of security properties

## Testing

The test suite includes comprehensive coverage of security features:

- Constant-time validation tests
- CanonicalHash invariant tests
- Stellar memo validation tests
- HashRegistry duplicate prevention tests
- Canonicalization enforcement tests
- Error handling tests

Run tests with:
```bash
cargo test hash_validator
```

## Migration Guide

### For Existing Code

**Before**:
```rust
let normalized = HashValidator::normalize(hash);
HashValidator::validate_sha256(&normalized)?;
```

**After** (security-sensitive):
```rust
HashValidator::validate_sha256_constant_time(hash)?;
```

**After** (with canonical type):
```rust
let canonical = CanonicalHash::new(hash)?;
```

### At API Boundaries

**Before**:
```rust
let hash = user_input.trim().to_lowercase();
```

**After**:
```rust
let canonical = HashValidator::enforce_canonical(user_input)?;
```

## References

- [subtle crate](https://docs.rs/subtle/) - Constant-time cryptography primitives
- [Stellar Memo Format](https://developers.stellar.org/docs/learn/fundamentals/transactions/memos)
- [Timing Attacks](https://en.wikipedia.org/wiki/Timing_attack)

## Version History

- **v1.0** - Initial security enhancements
  - Constant-time validation
  - CanonicalHash type
  - Stellar memo validation
  - Hash registry
  - Service boundary canonicalization
