# Cryptography Implementation Guide

> Cryptography standards for symmetric encryption, digital signatures, password hashing, and key management.

## Overview

This document defines which cryptographic algorithms to use, how to configure them correctly, and which algorithms to avoid. Following these standards ensures compliance with SOC 2 CC6.7, PCI-DSS Req 4, and HIPAA 164.312(e)(1). The project's `security_scanner.py` detects violations of these standards through SAST pattern matching.

**Audience:** Engineers implementing cryptographic operations in application code.

---

## Symmetric Encryption

### Recommendation: AES-GCM

**AES-GCM** (Advanced Encryption Standard in Galois/Counter Mode) is the recommended symmetric encryption algorithm. It provides both confidentiality and integrity (authenticated encryption).

**Configuration:**
- **Key size:** 256 bits (preferred). 128 bits acceptable if constrained.
- **Nonce/IV:** 12 bytes (96 bits). Must be generated with a cryptographically secure random number generator.
- **Never reuse a nonce with the same key** — doing so breaks all security guarantees.

```python
import os
from cryptography.fernet import Fernet

# Generate key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt (nonce is handled automatically by Fernet)
token = cipher.encrypt(b"secret data")

# Decrypt
plaintext = cipher.decrypt(token)
```

**Authentication tag verification:** Always verify the tag before using decrypted data. GCM's tag provides integrity — if verification fails, the data has been tampered with. Do not use decrypted data before verifying the tag.

### What to Avoid

| Algorithm | Issue | Replacement |
|-----------|-------|-------------|
| AES-ECB | Deterministic; identical plaintext blocks produce identical ciphertext | AES-GCM |
| AES-CBC | Requires padding; vulnerable to padding oracle attacks | AES-GCM |
| DES / 3DES | 56-bit / 112-bit keys — brute-force feasible | AES-256-GCM |

---

## Asymmetric Signatures

### Recommendation: Ed25519

**Ed25519** provides digital signatures with strong security and excellent performance characteristics.

**Advantages over ECDSA:**
- **Deterministic:** Same message always produces the same signature (no random nonce missteps)
- **Constant-time:** No timing side channels
- **Smaller signatures:** 64 bytes vs ECDSA's ~70-72 bytes
- **Simpler implementation:** Resistant to common implementation bugs

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generate key pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Sign
signature = private_key.sign(b"message")

# Verify
public_key.verify(signature, b"message")
```

### RSA Deprecation

- RSA-2048 is acceptable for legacy systems but not recommended for new implementations
- RSA-1024 is prohibited for any security-sensitive operation
- **Timeline:** Migrate from RSA to Ed25519 by end of 2027

| Algorithm | Key Size | Status |
|-----------|----------|--------|
| RSA | 4096+ | Acceptable for legacy |
| RSA | 2048 | Acceptable for legacy |
| RSA | 1024 | Prohibited |
| ECDSA | P-256 / P-384 | Acceptable |
| Ed25519 | 256-bit | **Recommended** |

---

## Password Hashing

### Recommendation: Argon2id

**Argon2id** is the recommended password hashing algorithm (winner of the PHC competition). It is resistant to both GPU and side-channel attacks.

```python
from argon2 import PasswordHasher

ph = PasswordHasher(
    memory_cost=65536,       # 64 MB
    time_cost=3,             # 3 iterations
    parallelism=1,           # 1 thread
    hash_len=32,             # 32-byte output
    salt_len=16,             # 16-byte salt
)
```

### Acceptable: bcrypt (Legacy)

bcrypt is acceptable for existing systems but should not be used for new implementations.

```python
import bcrypt

salt = bcrypt.gensalt(rounds=12)  # Minimum cost factor: 12
hash = bcrypt.hashpw(password.encode(), salt)
```

| Algorithm | Parameters | Status |
|-----------|-----------|--------|
| Argon2id | 64MB memory, 3 iterations, 1 thread | **Recommended** for new systems |
| bcrypt | Cost factor 12+ | Acceptable for legacy |
| scrypt | — | Acceptable if Argon2 not available |
| PBKDF2 | — | Avoid if possible |
| MD5/SHA-1 hashing of passwords | — | **Prohibited** |

---

## Key Management

### HSM vs Software Vaults

| Approach | Security Level | Best For |
|----------|---------------|----------|
| Hardware Security Module (HSM) | Highest — keys never leave hardware | Payment systems, CA operations |
| Software vault (Vault, AWS KMS, GCP Cloud KMS) | High — keys encrypted at rest with access control | Most applications |
| Environment variables | Low — keys in process memory | Local development only |

### Key Derivation

Use **HKDF** (HMAC-based Key Derivation Function) to derive sub-keys from a master key.

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"application-specific-context",
)
derived_key = hkdf.derive(master_key)
```

### Key Rotation Schedule

| Key Type | Rotation Period | Notes |
|----------|----------------|-------|
| TLS certificate | 90 days | Automate with ACME / cert-manager |
| Symmetric encryption key | 1 year | Re-encrypt data with new key |
| Signing key | 1 year | Verify old signatures with old key |
| API key / secret | 90 days | Rotate immediately on compromise |

### Emergency Key Destruction

Procedure for destroying keys when a compromise is detected:
1. Identify all systems using the compromised key
2. Immediately issue new keys
3. Migrate systems to new keys
4. Rotate the old key out of storage
5. Verify old key is no longer accepted by any system
6. Document the compromise and rotation in an incident report

---

## What Not to Use

| Algorithm | Reason | Severity |
|-----------|--------|----------|
| MD5 | Collision attacks — can forge signatures | Critical |
| SHA-1 | Collision attacks (SHAttered, SHambles) | Critical |
| ECB mode | Identical plaintext blocks produce identical ciphertext | High |
| RC4 | Biased output — can recover plaintext | Critical |
| Custom crypto | Always broken — attackers have years to analyze it | Critical |
| Non-constant-time comparison | Timing side channel leaks secrets (use `hmac.compare_digest`) | High |
| Pseudo-random generators (random, rand) | Predictable output — not suitable for security | Critical |

---

## Tool Mapping

| Practice | Checked By | Status |
|----------|-----------|--------|
| Weak crypto algorithm detection (MD5, SHA-1, ECB, RC4) | `security_scanner.py` (SAST patterns) | Automated |
| TLS version enforcement | `ssl_tls` module | Automated |
| Certificate expiry check | `ssl_tls` module | Automated |
| Password hashing algorithm | Manual code review | Manual |
| Key management procedures | Manual review | Manual |
| Nonce/IV reuse | Manual code review | Manual |
| Side-channel timing attacks | Manual code review | Manual |

---

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [IETF RFC 8439: ChaCha20-Poly1305 (alternative to AES-GCM)](https://datatracker.ietf.org/doc/html/rfc8439)
- [IETF RFC 8032: Ed25519 / Ed448](https://datatracker.ietf.org/doc/html/rfc8032)
- [IETF RFC 5869: HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [Password Hashing Competition (Argon2)](https://github.com/P-H-C/phc-winner-argon2)
- [NIST SP 800-57: Key Management Recommendations](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
