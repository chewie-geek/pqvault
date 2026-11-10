# pqvault

Encrypt files and folders so they stay confidential even after large-scale
quantum computers exist, and sign them so recipients can prove who sent them.

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

# Signed: Alice encrypts to Bob and signs; Bob insists it came from Alice
pqvault encrypt contract.pdf -r bob.pub -s alice.key
pqvault decrypt contract.pdf.pqv -i bob.key --from alice.pub

# Reject anything Alice signed more than 7 days ago (stops replayed old files)
pqvault decrypt contract.pdf.pqv -i bob.key --from alice.pub --max-age 7d

# Sign without encrypting (e.g. publishing a release); anyone can verify
pqvault sign release.zip -i alice.key     # -> release.zip.sig
pqvault verify release.zip --from alice.pub

# Show a key's fingerprint
pqvault fingerprint alice.pub
```

### Trusting a public key

A signature proves a file came from whoever holds a given private key. It
can't tell you *whose* key that is. When someone sends you their `.pub` file,
compare its fingerprint (`pqvault fingerprint them.pub`) with them over a
channel you already trust: in person, or on a phone call where you recognize
their voice. After that, `--from them.pub` guarantees the file is theirs and
unmodified. Without `--from`, `decrypt` still checks the signature and shows
the signer's fingerprint, but leaves it to you to recognize it.

### Signing times

Every signature records when it was made, and `decrypt`/`verify` print it.
The time is covered by the signature, so nobody can change it without
breaking the signature. Use `--max-age` (`90s`, `30m`, `12h`, `7d`, `2w`) to
reject files signed too long ago, which stops someone re-sending an old
signed file as if it were new.

The time comes from the **signer's own clock**. It proves when the signer
*says* they signed. A trusted signer with a wrong clock, or one who lies,
can put any time they want. Signatures dated more than 5 minutes in the
future get a warning, and `--max-age` rejects them.

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
| Signatures | **ML-DSA-65 (FIPS 204) + Ed25519 hybrid** | ML-DSA is NIST's post-quantum signature standard; both halves must verify, so forging needs to break both |
| Key derivation / header auth / hashing | HKDF-SHA256, HMAC-SHA256, SHA-512 | Symmetric |

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

**Signed files** (flag `0x02`) end the *plaintext* with a trailer:
`signing time ‖ signer public key ‖ hybrid signature`. Because it's inside
the encryption, only recipients learn who signed. The signature covers
`signing time ‖ SHA-512(header) ‖ SHA-512(signer key) ‖ SHA-512(data)`. Binding the header
ties it to this exact set of recipients, so a recipient can't re-encrypt a
signed file to someone else and have it still appear to come from the sender.

### Keys

A keypair holds both an encryption key (ML-KEM-768 + X25519) and a signing key
(ML-DSA-65 + Ed25519). Public keys start with `pqv2pub:`. Keys made by
pqvault 0.1 (`pqv1pub:`) still work for encryption but can't sign. The
fingerprint is a hash of the *whole* public key, so nobody can attach
someone else's signing key to their own encryption key.

## Threat model

**Protects against**
- An attacker who stores your encrypted files today and later has a quantum
  computer ("harvest now, decrypt later").
- Tampering with or truncating an encrypted file. This is detected, and no output is produced.
- Forged senders. With `--from`, a file that isn't validly signed by that key is rejected
  and nothing is written. This holds against quantum attackers too.
- Brute-forcing passwords. Argon2id makes each guess expensive, **but a weak password is still weak**.

**Does not protect against**
- Malware or anyone with access to your unlocked computer.
- A stolen private-key file *plus* its passphrase.
- Leaking file sizes. Ciphertext size is about the plaintext size.
- Someone handing you a fake public key. Check fingerprints (see above).
- A signed file being *replayed* within its `--max-age` window. pqvault
  doesn't remember which files it has already seen.
- A signer lying about the time. Timestamps come from the signer's clock, not a
  trusted timestamping service.

## Development

```bash
.venv/bin/pytest
```
