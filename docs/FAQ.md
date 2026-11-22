# FAQ

Common questions, roughly ordered by how often they come up.

## Which handler should I use?

If you have no opinion, **Sodium**. The construction has no knobs, the
defaults are correct, and the cryptography is modern. Pick OpenSSL only
if you have a concrete reason: FIPS compliance, custom cipher
requirements, or libsodium-isn't-available environments.

See [Sodium Handler](Sodium-Handler.md) and [OpenSSL Handler](OpenSSL-Handler.md).

## Why hex output, not base64?

Three reasons:

1. **URL-, cookie-, JSON-safe everywhere without escaping.** Base64
   needs `base64url` to be URL-safe; hex is URL-safe by default.
2. **Easier to debug.** `02006f1c...` immediately tells you "this is a
   v2 ciphertext, JSON serializer". A base64 string hides the format
   header.
3. **Cheap to detect tampering at the boundary.** Any non-hex character
   is rejected before any cryptographic work runs.

The cost is a 2× size factor over the raw binary. If you store millions
of ciphertexts and bytes matter, `hex2bin()` before storage and
`bin2hex()` again on read — the package's `encrypt()` / `decrypt()` only
ever speak hex on the public surface.

## Can I store ciphertexts in URLs / cookies / query strings?

Yes — hex is URL-safe. For cookies, set the usual `Secure`, `HttpOnly`,
`SameSite=Strict` flags. Watch for the 4 KB cookie size cap; a
ciphertext is roughly `2 × (header + IV/nonce + HMAC + payload)`
characters, so JSON payloads bigger than a few hundred bytes start to
encroach.

See [Recipes #1](Recipes.md#1-encrypted-session-cookie) and
[Recipes #3](Recipes.md#3-encrypted-url-token).

## Why JSON by default? My code uses `serialize`.

Because `unserialize()` on attacker-controlled bytes is the canonical
PHP object-injection vector, and "the bytes are HMAC-verified so the
attacker can't control them" is true **only as long as your key never
leaks.** JSON cannot instantiate classes — defense in depth.

If your payloads genuinely need PHP's serialization (binary blobs, deep
custom classes), pass `'serializer' => 'php_serialize'` explicitly. The
package always invokes `unserialize()` with `['allowed_classes' =>
false]` in that mode, so you still get a meaningful defense.

See [Serialization](Serialization.md).

## Can I disable the HMAC / authentication?

**No.** There is no "encrypt without authenticate" mode, and there
won't be. Authenticated encryption is the only encryption a modern
library should offer; the cost is negligible and the safety guarantees
are large.

If you have a legitimate need for unauthenticated encryption (you are
streaming gigabytes and want to authenticate the whole stream at the
end), this package is the wrong tool — use `openssl_encrypt()` directly.

## Does the package support streaming encryption?

Not in 2.x. Both handlers operate on the full payload in memory.

For large blobs:

- libsodium has `crypto_secretstream_xchacha20poly1305_*`, which is the
  right primitive for streaming AEAD. Build a custom handler around it —
  see [Custom Handlers](Custom-Handlers.md).
- For OpenSSL streaming, `openssl_encrypt`/`openssl_decrypt` operate on
  full buffers; you would need to use `ext-openssl`'s stream filter
  machinery directly, which is outside the package's scope.

## Two encrypts of the same plaintext return different ciphertexts. Is that a bug?

No, that's a feature. OpenSSL uses a fresh random IV per call; Sodium
uses a fresh random nonce. If two ciphertexts of the same plaintext were
identical, an attacker could deduce that the plaintexts match without
ever decrypting either.

If you need deterministic encryption (e.g. for a database equality
index), the package is the wrong tool — that requires a separate
construction (synthetic IV, FF1, …) with different security properties.

## Can two PHP processes encrypt with handler A and decrypt with handler B?

Two processes using the **same handler class** and the **same options**
will interoperate. Sodium key derivation and OpenSSL HKDF are both
deterministic on the user key.

You **cannot** decrypt an OpenSSL ciphertext with the Sodium handler or
vice versa — the wire formats are different. The package's integration
test suite asserts this in both directions.

## How do I change the cipher / algo without breaking existing ciphertexts?

You can't, with the built-in handlers — the cipher and algorithm are not
recorded in the wire format. Decryption uses whatever the handler is
configured with at decrypt time.

If you want self-describing cipher choice, build a custom handler that
embeds a cipher ID in the payload (between the format header and the
ciphertext bytes). See the "Versioning Your Own Format" section in
[Custom Handlers](Custom-Handlers.md).

## Is `php_serialize` mode safe if I never set my own classes?

Effectively yes. `allowed_classes: false` means `unserialize()` returns
`__PHP_Incomplete_Class` for any custom class rather than instantiating
it — no constructor runs, no `__wakeup` / `__destruct` is triggered.

That said, JSON is *categorically* safer because no class metadata is
even parsed. Use JSON unless you have a concrete reason to use serialize.

## Why does `getOption('key')` still return the key after `sodium_memzero`?

The Sodium handler zeroes the **derived** key (the 32 bytes that go into
`crypto_secretbox`) before returning, but the user key — the one you
passed into the handler's options — lives in your `$options` array,
which is your buffer to manage.

If you want the user key wiped, manage that buffer yourself:

```php
$key = read_key_from_vault();
$handler = new \InitPHP\Encryption\Sodium(['key' => $key]);
// $handler now has the key inside its options array; that's the buffer
// you'll need to clear if you want it gone. Either trust the GC or
// hold a reference yourself for sodium_memzero().
$ct = $handler->encrypt($payload);
```

## Can I use this package to encrypt files?

For small files (anything that fits in PHP's `memory_limit`
comfortably) — yes. `encrypt(file_get_contents(...))` then
`file_put_contents(..., $ct)` works fine.

For large files, see "Does the package support streaming encryption?"
above. And [Recipes #4](Recipes.md#4-encrypted-file-on-disk) for the
small-file pattern.

## Why does composer.json say `^8.2`?

`^8.2` means "8.2 or any later 8.x". When 9.0 comes out, this constraint
prevents the package from auto-installing — intentional, since 9.0 will
probably have breaking language changes the package needs to verify
against first. A future 2.x release will widen the constraint.

## Where's the changelog?

[`CHANGELOG.md`](https://github.com/InitPHP/Encryption/blob/main/CHANGELOG.md)
at the repository root, in [Keep a Changelog](https://keepachangelog.com/)
format.

## I'm getting `Unsupported ciphertext format version 0x01; expected 0x02`. What now?

You have ciphertexts produced by 1.x trying to decode under 2.x. This is
the deliberate, designed BC break — see
[Migration from 1.x](Migration-from-1.x.md) for the re-encryption recipe.

## Is the package PSR-XX compliant?

The package does not implement any PSR interface — there isn't a PSR for
symmetric encryption. It does follow:

- **PSR-4** for autoloading (`InitPHP\Encryption\` → `src/`).
- **PER-CS** for code style (enforced by `composer cs-check` in CI).
- **PHPStan level 8** on the entire source tree.

## I have a question that isn't here.

Open a [GitHub Discussion](https://github.com/orgs/InitPHP/discussions/categories/q-a)
in the Q&A category. If the answer is a doc gap, the question ends up
answered here in the next release.
