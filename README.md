# pqvault

Encrypt files and folders so they stay confidential even after large-scale
quantum computers exist.

> **Status: early, unaudited software.** The design uses only standard, vetted
> primitives, but this code has not been independently reviewed. Keep backups,
> and don't rely on it as the only protection for critical data yet.

## Install (development)

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pqvault --help
```

## Usage

```bash
# Password-protected
pqvault encrypt taxes.pdf -p              # -> taxes.pdf.pqv
pqvault decrypt taxes.pdf.pqv             # -> taxes.pdf

# Keypairs (encrypt to someone without sharing a secret)
pqvault keygen -o alice                   # alice.pub (share), alice.key (secret)
pqvault encrypt photos/ -r alice.pub -r bob.pub
pqvault decrypt photos.pqv -i alice.key

# Mix: openable by password OR by Alice's key
pqvault encrypt notes.txt -p -r alice.pub
```

Passwords are always entered at a hidden prompt, never on the command line.
Output is written to a temporary file and only moved into place once the
entire file has been authenticated, so a corrupted or tampered file never
leaves partial plaintext behind.

## Cryptographic design

| Purpose | Algorithm | Why it survives quantum computers |
|---|---|---|
| Bulk data | AES-256-GCM, 64 KiB chunks (STREAM) | Grover's algorithm only halves symmetric strength: 256 → ~128-bit |
| Password → key | Argon2id (256 MiB, 3 passes) | Symmetric; memory-hard against GPU/ASIC guessing |
| Public-key exchange | **ML-KEM-768 (FIPS 203) + X25519 hybrid** | ML-KEM is NIST's post-quantum standard; X25519 is a classical safety net in case a flaw is found in ML-KEM. An attacker must break both. |
| Key derivation / header auth | HKDF-SHA256, HMAC-SHA256 | Symmetric |

All primitives come from [`cryptography`](https://cryptography.io) (OpenSSL).
No cryptographic primitive is implemented in this project.

### File format (`.pqv`, version 1)

```
"PQV1" | version u8 | header_len u32 | header | HMAC-SHA256(header) | payload
header = flags u8 | payload_salt[16] | n u16 | n × (type u8 | len u32 | body)
```

A random 256-bit **file key** is wrapped once per *stanza*:

- **Password stanza:** Argon2id salt and parameters, plus the file key wrapped with AES-256-GCM.
- **Recipient stanza:** ML-KEM-768 ciphertext, an ephemeral X25519 public key, and the wrapped file key.
  The wrap key is `HKDF(ss_mlkem ‖ ss_x25519, info = label ‖ ciphertexts ‖ recipient_pk)`.

The payload key is `HKDF(file_key, salt = payload_salt)`. Each chunk's nonce is
`counter ‖ last-chunk flag`, so reordering, truncation and appended data are
all detected.

## Threat model

**Protects against**
- An attacker who stores your encrypted files today and later has a quantum
  computer ("harvest now, decrypt later").
- Tampering with or truncating an encrypted file. This is detected, and no output is produced.
- Brute-forcing passwords. Argon2id makes each guess expensive, **but a weak password is still weak**.

**Does not protect against**
- Malware or anyone with access to your unlocked computer.
- A stolen private-key file *plus* its passphrase.
- Leaking file sizes. Ciphertext size is about the plaintext size.
- Proving who sent a file. There are no signatures yet (planned: ML-DSA).

## Development

```bash
.venv/bin/pytest
```
