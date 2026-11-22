# Security Best Practices

This page is the package's threat model: what `initphp/encryption` defends
against, what it does not, and the operational practices you need to add
for the whole thing to be useful in production.

For *reporting* a vulnerability, see [`SECURITY.md`](https://github.com/InitPHP/.github/blob/main/SECURITY.md).
This page is the design context behind it.

## Threat Model

We assume an attacker who can:

- See, store, modify or replay any ciphertext your application produces.
- Submit arbitrary input to `decrypt()` — random bytes, hex of someone
  else's ciphertext, bytes they crafted.
- See timing of `decrypt()` calls.

We assume the attacker **cannot**:

- Read process memory.
- Read your `key` from your secret store.
- Modify the package source code at runtime.

Given those assumptions, the package guarantees:

1. **Confidentiality of plaintext.** An attacker who sees a ciphertext
   cannot recover the plaintext without the key.
2. **Integrity of ciphertext.** Any modification — single bit flip, byte
   rearrangement, truncation, extension — is detected and rejected.
   `decrypt()` will never return a value that was not produced by
   `encrypt()` with the same key.
3. **Bound on what `decrypt()` does with attacker bytes.** Even the
   `php_serialize` serializer is invoked with `allowed_classes: false`,
   so `decrypt()` cannot instantiate arbitrary application classes via
   PHP's gadget-chain machinery, *even if* the attacker obtains the key.
4. **No silent failure.** A failed decrypt always throws — never returns
   `null`, `false`, or a corrupted value.

What the package does **not** guarantee:

- **Confidentiality of plaintext length.** Ciphertexts grow with their
  plaintext. The Sodium handler can mitigate via `blocksize`; the OpenSSL
  handler cannot.
- **Confidentiality of plaintext existence.** That you `encrypt()`-ed
  something is observable to anyone watching your process.
- **Forward secrecy.** If your key is later compromised, every ciphertext
  ever produced with that key is decryptable. Rotate keys to bound the
  blast radius.
- **Resistance to brute-force search of weak keys.** Key derivation
  cannot add entropy. A user key of `"password"` is worth roughly nothing.

## Cryptographic Constructions

### OpenSSL handler

- **Key derivation**: `hash_hkdf($algo, $userKey)`. Output length equals
  the hash output size (32 bytes for SHA-256) regardless of user key length.
- **Encryption**: `openssl_encrypt(..., OPENSSL_RAW_DATA, $iv)` with a
  fresh random IV per call via `random_bytes()` (OS CSPRNG).
- **Authentication**: HMAC-SHA-N over `VERSION || SERIALIZER || IV ||
  ciphertext`. Comparison uses `hash_equals()` (constant-time).
- **Encoding**: hex.

The construction is *encrypt-then-MAC* with a single derived key for both
operations. The HMAC covers the format header so an attacker cannot flip
the serializer byte to coax a different deserialisation path.

### Sodium handler

- **Key derivation**: BLAKE2b via `sodium_crypto_generichash($userKey,
  '', 32)`. The derived key lives in a local buffer and is zeroed via
  `sodium_memzero()` in a `finally` block.
- **Encryption + authentication**: `sodium_crypto_secretbox()`
  (XSalsa20-Poly1305). The Poly1305 MAC is part of the construction.
- **Nonce**: 24 random bytes per call. Collision probability is
  negligible at this size — you can encrypt billions of messages per key
  without practical risk.
- **Padding**: `sodium_pad()` before encryption, `sodium_unpad()` after.
- **Encoding**: hex.

## Generating a Key

```bash
php -r 'echo bin2hex(random_bytes(32)), "\n";'
# → 64-character hex string, 256 bits of entropy
```

That string goes into your secret store. Do **not** commit it to a
repository.

## Storing the Key

In order of preference:

1. **A dedicated secrets manager** (AWS Secrets Manager / GCP Secret
   Manager / HashiCorp Vault / Doppler / 1Password Secrets Automation /
   …). The right answer for any real production deployment.
2. **An environment variable injected at process start** (Kubernetes
   `Secret`, systemd `EnvironmentFile`, Docker `secret`, your platform's
   equivalent).
3. **A `.env` file outside the document root**, owned by the PHP user,
   `chmod 600`. Appropriate for small deployments, not for anything with
   regulatory exposure.

What you must not do:

- Commit the key to git.
- Put the key in a file under the document root.
- Pass the key on the command line (`ps`, shell history).
- Log the key anywhere — including "debug" builds.

## Rotating the Key

Plan for rotation from day one. The minimal-disruption recipe:

```php
use InitPHP\Encryption\Sodium;
use InitPHP\Encryption\Exceptions\EncryptionException;

$newKey = getenv('APP_ENCRYPTION_KEY');
$oldKey = getenv('APP_ENCRYPTION_KEY_PREVIOUS');

// All encrypts use the new key:
$writer = new Sodium(['key' => $newKey]);

// Decrypts try the new key first, fall back to the old one:
function decryptWithRotation(string $ct, string $newKey, ?string $oldKey): mixed
{
    try {
        return (new Sodium(['key' => $newKey]))->decrypt($ct);
    } catch (EncryptionException) {
        if ($oldKey === null || $oldKey === '') {
            throw new RuntimeException('decrypt failed and no fallback key available');
        }
        return (new Sodium(['key' => $oldKey]))->decrypt($ct);
    }
}
```

After every stored ciphertext has been re-encrypted under the new key,
drop `APP_ENCRYPTION_KEY_PREVIOUS` from the secret store. See
[Recipes #6](Recipes.md#6-key-rotation-with-fallback-decrypt) for the
re-encryption loop.

## Compromise Response

If you suspect the key has leaked:

1. Generate a new key.
2. Deploy with both keys present (rotation pattern above).
3. Re-encrypt every stored ciphertext.
4. Drop the old key from the secret store.
5. Audit access to the key store: who saw it, when, from where.

Every ciphertext encrypted under the leaked key is *retroactively
decryptable* by the attacker. Forward secrecy is not part of the package's
guarantee — if leak is a realistic concern, design your system so that
ciphertexts that have outlived their useful life are *deleted*, not just
re-encrypted.

## Ciphertext Storage

- **Cookies, URL parameters, query strings**: fine. Hex is URL-safe.
  Always set `HttpOnly`, `Secure`, `SameSite=Strict` on cookies.
- **Databases**: fine. Store as `TEXT` / `VARCHAR`. Hex doubles the byte
  size; if storage cost matters, `hex2bin()` before insert and `bin2hex()`
  on read.
- **Logs and error messages**: do not log ciphertext. It is not plaintext,
  but it is sensitive — it can leak query patterns and would be useful to
  an attacker if a future primitive break is found.
- **Public anonymous responses**: only if the ciphertext is *meant* to
  round-trip back to your service (session cookie, magic link). A leaked
  ciphertext has no business being public.

## Side Channels

- **Timing**. HMAC comparison uses `hash_equals()` (constant-time).
  Sodium's `secretbox_open` is constant-time by construction. The package's
  hex-decode, format checks, and option resolution are *not*
  constant-time — they reveal "this didn't pass the size check" vs "this
  failed at the MAC step", but the difference is not load-bearing in the
  threat model above.
- **Memory**. Sodium's derived key is wiped via `sodium_memzero()` in a
  `finally` block. The user key you handed in is not — managing that
  buffer is your responsibility.
- **Cache / Spectre / Meltdown**. Out of scope. If you run untrusted
  co-tenants on the same machine, no userland crypto library can help.

## Recommended Defaults

If you have no strong opinion, use:

```php
use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\Sodium;

$handler = Encrypt::use(Sodium::class, [
    'key' => getenv('APP_ENCRYPTION_KEY'),
    // 'serializer' => 'json',   ← default
    // 'blocksize'  => 16,       ← default
]);
```

This is XSalsa20-Poly1305 AEAD with a 256-bit derived key, JSON-serialized
payloads, and 16-byte length padding. There is nothing else to tune.

## See Also

- [Sodium Handler](Sodium-Handler.md) — implementation details.
- [Error Handling](Error-Handling.md) — what an attacker may have triggered
  to produce each message.
- [Migration from 1.x](Migration-from-1.x.md) — what the format change
  guarantees about old ciphertexts.
- [Recipes](Recipes.md#6-key-rotation-with-fallback-decrypt) — practical
  rotation code.
