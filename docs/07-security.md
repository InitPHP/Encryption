# Security

This document is the package's threat model: what `initphp/encryption`
defends against, what it does not, and the operational practices you need
to add for the whole thing to be useful in production.

For *reporting* a vulnerability, see [`SECURITY.md`](../SECURITY.md). This
file is the design context behind it.

## Threat Model

We assume an attacker who can:

- See, store, modify or replay any ciphertext your application produces.
- Submit arbitrary input to `decrypt()` — random bytes, hex of someone
  else's ciphertext, bytes they generated themselves.
- See timing of `decrypt()` calls.

We assume the attacker **cannot**:

- Read process memory.
- Read your `key` from your secret store.
- Modify the package source code at runtime.

Given those assumptions, the package guarantees:

1. **Confidentiality of plaintext.** An attacker who sees a ciphertext
   cannot recover the plaintext without the key.
2. **Integrity of ciphertext.** Any modification — single bit flip, byte
   rearrangement, truncation, extension — is detected and rejected with
   `EncryptionException`. `decrypt()` will never return a value that was not
   produced by `encrypt()` with the same key.
3. **Bound on what `decrypt()` does with attacker bytes.** Even the
   `php_serialize` serializer is invoked with `allowed_classes: false`, so
   `decrypt()` cannot instantiate arbitrary application classes via PHP's
   gadget-chain machinery, even if an attacker somehow obtained the key.
4. **No silent failure.** A failed decrypt always throws — never returns
   `null`, `false`, or a corrupted value.

What the package does **not** guarantee:

- **Confidentiality of plaintext length.** Ciphertexts grow with their
  plaintext. The Sodium handler can mitigate this with `blocksize`; the
  OpenSSL handler cannot.
- **Confidentiality of plaintext existence.** That you `encrypt()`'d
  something is observable to anyone watching your process. The Sodium nonce
  and OpenSSL IV are randomly different each call, so two ciphertexts of the
  same plaintext look unrelated — but the fact that *a* ciphertext exists
  is unhidden.
- **Forward secrecy.** If your key is later compromised, every ciphertext
  ever produced with that key is decryptable. Rotate keys (see below) to
  bound the blast radius.
- **Resistance to a brute-force search of weak keys.** The handler derives
  a key of the correct length from arbitrary input, but no derivation can
  add entropy. A user key of `"password"` is worth roughly nothing.

## Cryptographic Constructions

### OpenSSL handler

- **Key derivation**: `hash_hkdf($algo, $userKey)`. Output length equals the
  hash output (32 bytes for SHA-256, etc.) regardless of `$userKey` length.
- **Encryption**: `openssl_encrypt(..., OPENSSL_RAW_DATA, $iv)` with a fresh
  random IV per call (via `random_bytes()`, the OS CSPRNG).
- **Authentication**: HMAC-SHA-N over `VERSION || SERIALIZER || IV ||
  ciphertext`. Comparison uses `hash_equals()` to avoid timing leaks.
- **Encoding**: hex.

The construction is *encrypt-then-MAC* with a single derived key for both
operations. The HMAC covers the format header so an attacker cannot flip
the serializer byte to coax a different deserialization path.

### Sodium handler

- **Key derivation**: BLAKE2b via `sodium_crypto_generichash($userKey, '',
  32)`. The derived key is held in a local buffer and zeroed via
  `sodium_memzero()` in a `finally` block.
- **Encryption + authentication**: `sodium_crypto_secretbox()`
  (XSalsa20-Poly1305). The Poly1305 MAC is part of the construction.
- **Nonce**: 24 random bytes per call (`random_bytes()`). At 24 bytes the
  collision probability is negligible — you can encrypt billions of
  messages per key without practical risk.
- **Padding**: `sodium_pad()` before encryption / `sodium_unpad()` after, to
  reduce plaintext-length leakage.
- **Encoding**: hex.

## Key Management

The package is only as secure as your key handling.

### Generating a Key

```bash
php -r 'echo bin2hex(random_bytes(32)), "\n";'
# → 64-character hex string, 256 bits of entropy
```

That goes into your secret store. Do **not** commit it to the repository.

### Storing the Key

In order of preference:

1. A dedicated secrets manager (AWS Secrets Manager / GCP Secret Manager /
   HashiCorp Vault / Doppler / 1Password Secrets Automation).
2. An environment variable populated at process start by your orchestrator
   (Kubernetes `Secret`, systemd `EnvironmentFile`, Docker secrets).
3. A `.env` file outside the document root, chmod 600, owned by the PHP
   process user. The bottom rung — appropriate for small deployments, not
   for anything with regulatory exposure.

What you must not do:

- Commit the key into git.
- Put the key in a file under the document root.
- Pass the key on the command line (visible to `ps` and shell history).
- Log the key, even in debug builds.

### Rotating the Key

Plan for rotation from day one. The recipe for a hot-rotation without
downtime:

```php
// 1) Read both keys; new one is preferred for encryption.
$oldKey = getenv('APP_ENCRYPTION_KEY_PREVIOUS');
$newKey = getenv('APP_ENCRYPTION_KEY');

// 2) All encrypts use the new key.
$writer = Encrypt::use(Sodium::class, ['key' => $newKey]);

// 3) Decrypts try the new key first, fall back to the old one.
function decryptWithRotation(string $ct, string $newKey, ?string $oldKey): mixed
{
    try {
        return (new Sodium(['key' => $newKey]))->decrypt($ct);
    } catch (\InitPHP\Encryption\Exceptions\EncryptionException) {
        if ($oldKey === null || $oldKey === '') {
            throw new RuntimeException('decrypt failed and no fallback key available');
        }
        // Old key proves the cipher is from the previous epoch; opportunistically
        // re-encrypt and persist with the new key from the caller.
        return (new Sodium(['key' => $oldKey]))->decrypt($ct);
    }
}
```

After every stored ciphertext has been re-encrypted under the new key, drop
`APP_ENCRYPTION_KEY_PREVIOUS` from the secret store.

Caveat: every failed decrypt now triggers two MAC checks instead of one.
That's a fixed cost, not an attacker-amplifiable one.

### Compromise Response

If you suspect the key has leaked:

1. Generate a new key.
2. Deploy with both keys present (as in the rotation pattern above).
3. Re-encrypt every stored ciphertext.
4. Drop the old key from secrets.
5. Audit access to the key store: who saw it, when, from where.

Every ciphertext encrypted under the leaked key is *retroactively
decryptable* by the attacker. Forward secrecy is not part of the package's
guarantee — if leak is a realistic concern, design your system so that
ciphertexts that survive past their useful life are deleted, not just
re-encrypted.

## Ciphertext Storage

- **Cookies and URL parameters**: fine. Hex is URL-safe. Set
  `HttpOnly`, `Secure`, `SameSite=Strict` on cookies as usual.
- **Databases**: fine. Store as `TEXT` / `VARCHAR`. Hex doubles the byte
  size; if storage cost matters, base64-decode-then-store, but that is an
  application choice the package does not currently make for you.
- **Logs and error messages**: do not log ciphertext. It is not plaintext,
  but it is sensitive (it tells an attacker what queries you encrypted, and
  reveals the ciphertext for future cryptanalysis if a primitive break is
  ever found).
- **Public artefacts (web responses to anonymous users)**: only if the
  ciphertext is *meant* to round-trip back to your service. A session
  cookie, fine. A leaked ciphertext otherwise has no business being public.

## Side Channels

- **Timing**: HMAC comparison uses `hash_equals()` (constant-time). Sodium's
  secretbox open is constant-time by construction. The OpenSSL handler's
  hex-decode, format checks, and option resolution are *not* constant-time
  — they reveal "this didn't even pass the size check" vs "this failed at
  the MAC step", but the difference is not load-bearing in the threat model
  above.
- **Memory**: Sodium's derived key is wiped via `sodium_memzero()`. The
  user-supplied key is not; it lives wherever the caller put it.
- **Cache / Spectre / Meltdown**: out of scope. If you run untrusted
  co-tenants on the same machine, no userland crypto library can help you.

## Recommended Defaults

If you have no strong opinion, use:

```php
use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\Sodium;

$handler = Encrypt::use(Sodium::class, [
    'key' => getenv('APP_ENCRYPTION_KEY'),
    // 'serializer' => 'json',   // default
    // 'blocksize' => 16,        // default
]);
```

This is XSalsa20-Poly1305 AEAD with a 256-bit derived key, JSON-serialized
payloads, and 16-byte length padding. There is nothing else to tune.

## See Also

- [03 — Sodium Handler](./03-sodium-handler.md) — implementation details of
  the AEAD construction.
- [06 — Error Handling](./06-error-handling.md) — every error message and
  what an attacker may have triggered to produce it.
- [`SECURITY.md`](../SECURITY.md) — how to report a vulnerability.
