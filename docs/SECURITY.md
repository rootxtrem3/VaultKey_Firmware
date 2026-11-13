# Security design and production notes

## Key hierarchy

1. First-time setup generates a random 256-bit master key using the ESP32-S3
   hardware random source.
2. A random 128-bit PIN salt is generated.
3. PBKDF2-HMAC-SHA256 derives a key-encryption key from the PIN. The device
   benchmarks PBKDF2 during setup for an approximately 750 ms derivation and
   clamps the saved count to 50,000–600,000 iterations.
4. AES-256-GCM wraps the random master key. The salt, iteration count, nonce,
   wrapped key, and tag form a versioned NVS envelope.
5. HKDF-SHA256 derives independent credential-record, TOTP-record, and manifest
   keys from the master key.

Changing the PIN re-wraps the same random master key with a new salt, nonce,
and benchmarked KDF count. Records do not need to be decrypted and rewritten.

## Record storage

- Credentials and TOTP entries are individually encoded and encrypted with
  AES-256-GCM.
- Every write obtains a new random 96-bit GCM nonce.
- The version, record type, ID, ciphertext length, and nonce are authenticated
  as additional data.
- Authentication tags are checked before record decoding or display.
- An encrypted manifest authenticates the committed record-ID set.
- Writes use a verified temporary file, backup rename, and final rename.
- New records are committed to the manifest after their record file. Deletes
  are committed to the manifest before removing the old file. Boot recovery
  restores interrupted renames and removes uncommitted orphan files.
- A provisioned device never auto-formats LittleFS after a mount failure.

## Locking and temporary data

- Lock clears the master key, all three derived storage keys, decrypted index
  metadata, PIN-entry buffers, revealed passwords, TOTP secrets, provisioning
  authorization, USB protocol input, and pending HID text as far as practical.
- AES-GCM decryption failures zero the output buffer.
- Wrong PINs create a persisted exponential delay from 1 to 256 seconds.
- HID output requires unlock, per-action confirmation, and a ready HID host.
- CDC provisioning requires unlock plus a five-minute authorization from the
  physical UI. Protocol responses never echo passwords or TOTP secrets.

Every boot runs AES-256-GCM, PBKDF2-HMAC-SHA256, HKDF-SHA256, and all official
RFC 6238 SHA-1/SHA-256/SHA-512 known-answer vectors through the production
mbedTLS path. Failure stops security initialization instead of continuing.

## Factory reset

Factory reset requires PIN reauthentication and a two-second SELECT hold. It
removes record files, manifest, application settings, and the wrapped master
key. Deleting the master-key envelope is a cryptographic erase even if flash
wear-leveling prevents guaranteed physical overwriting of every old cell.

Before deleting anything, firmware commits a `wipe_pending` marker in NVS.
Startup resumes the wipe after an interruption and clears that marker only
after storage, settings, and key-envelope removal succeed. If individual file
deletion fails during this explicitly authorized operation, LittleFS is
formatted before key destruction.

Hardware EN reset and software restart never invoke this path.

## Development versus production security

This build deliberately does **not** burn eFuses or enable irreversible
settings. In particular it does not enable secure boot, flash encryption, NVS
encryption, disable JTAG, disable ROM download, or burn USB PHY selection.

For a production revision, evaluate ESP32-S3 flash encryption, secure boot,
NVS encryption, signed update policy, and debug/download policy on sacrificial
hardware first. Preserve an authorized recovery path before locking eFuses.

## Residual risks

- A six-digit PIN has low entropy. PBKDF2 slows offline guessing but cannot
  make six digits equivalent to a strong passphrase.
- Without ESP32 flash encryption, an attacker with physical flash access can
  copy ciphertext and the wrapped-key envelope for offline PIN guessing.
- CDC provisioning is authorization-gated but not transport-encrypted; the
  directly connected host sees submitted plaintext.
- Arduino `std::string`, JSON parsing, NVS, LittleFS, and wear leveling do not
  guarantee forensic erasure of every prior RAM/flash copy.
- The implementation has not received an independent security audit.
- Physical fault injection, side channels, malicious USB hosts, and supply
  chain attacks are outside the first-prototype threat model.

Do not store real production secrets until physical testing and an independent
security review are complete.
