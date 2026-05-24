# FAQ

Common questions, organised roughly by how often they come up.

## "Which handler should I use?"

If you have no opinion, **Sodium**. The construction has no knobs, the
defaults are correct, and the cryptography is modern. Pick OpenSSL only if
you have a concrete reason: FIPS compliance, custom cipher requirements, or
libsodium-isn't-available environments.

See [03 — Sodium Handler](./03-sodium-handler.md) and
[02 — OpenSSL Handler](./02-openssl-handler.md).

## "Why hex output, not base64?"

Three reasons:

1. **URL-, cookie-, JSON-safe everywhere without escaping.** Base64 needs
   `base64url` to be URL-safe; hex is URL-safe by default.
2. **Easier to debug.** `02006f1c...` immediately tells you "this is a v2
   ciphertext, JSON-serialized". A base64 string hides the format header.
3. **Cheap to detect tampering at the boundary.** Any non-hex character is
   rejected before any cryptographic work runs.

The cost is a 2× size factor over the raw binary. If you store millions of
ciphertexts and bytes matter, run `hex2bin()` before storage and `bin2hex()`
again on read — the package's `encrypt()` / `decrypt()` only ever speak hex
on the public surface.

## "Can I store ciphertexts in URLs / cookies / query strings?"

Yes — hex is URL-safe. For cookies, set the usual `Secure`, `HttpOnly`,
`SameSite=Strict` flags. Ciphertext length is roughly `2 * (header + IV/nonce
+ HMAC + payload)`, so be mindful of the 4 KB cookie limit if you put a lot
in there.

## "Why JSON by default? My code uses `serialize`."

Because `unserialize()` on attacker-controlled bytes is the canonical PHP
object-injection vector, and "the bytes are HMAC-verified so the attacker
can't control them" is true *only as long as your key never leaks*. JSON
cannot instantiate classes — defense in depth.

If your payloads genuinely need PHP's serialization (binary blobs, deeply
custom classes), pass `'serializer' => 'php_serialize'` explicitly. The
package always invokes `unserialize()` with `['allowed_classes' => false]`
in that mode, so you still get a meaningful defense.

See the table in [05 — Options Reference](./05-options.md#serializer).

## "Can I disable the HMAC / authentication?"

No. There is no "encrypt without authenticate" mode. Authenticated
encryption is the only encryption a modern library should offer; the most
common "I just want to hide bytes" use case has stronger guarantees with
authentication on than off.

If you have a legitimate need for unauthenticated encryption (e.g. you are
streaming gigabytes and want to authenticate the whole stream at the end),
this package is the wrong tool — use `openssl_encrypt()` directly.

## "Does the package support streaming encryption?"

Not in 2.x. Both handlers operate on the full payload in memory.

For large blobs:

- libsodium has `crypto_secretstream_xchacha20poly1305_*` which is the right
  primitive for streaming AEAD. You can build a custom handler around it —
  see [04 — Custom Handlers](./04-custom-handlers.md).
- For raw OpenSSL streaming, `openssl_encrypt`/`openssl_decrypt` operate on
  full buffers; you need to use `ext-openssl`'s stream filter machinery
  directly, which is outside the package's scope.

## "Two encrypts of the same plaintext return different ciphertexts. Is that a bug?"

No, that's a feature. OpenSSL uses a fresh random IV per call; Sodium uses
a fresh random nonce. If two ciphertexts of the same plaintext were
identical, an attacker could deduce that the plaintexts match without ever
decrypting either.

If you need deterministic encryption for, say, a database index, the
package is the wrong tool — that requires a separate construction
(synthetic IV, FF1, etc.) with different security properties.

## "Can two PHP processes encrypt with handler A and decrypt with handler B?"

Two processes using the **same** handler class and the **same** options
will interoperate. The Sodium key derivation and OpenSSL HKDF are both
deterministic on the user key.

You **cannot** decrypt an OpenSSL ciphertext with the Sodium handler or
vice versa — the wire formats are different and (intentionally) the
relevant integration test asserts this.

## "How do I change the cipher / algo without breaking existing ciphertexts?"

You can't, with the built-in handlers — the cipher and algorithm are not
recorded in the wire format. Decryption uses whatever the handler is
configured with at decrypt time.

If you want self-describing cipher choice, build a custom handler that
embeds a cipher ID in the payload (between the format header and the
ciphertext bytes). See the "Versioning Your Own Format" section in
[04 — Custom Handlers](./04-custom-handlers.md).

## "Is `php_serialize` mode safe if I never set my own classes?"

Effectively yes. `allowed_classes: false` means `unserialize()` returns
`__PHP_Incomplete_Class` for any custom class rather than instantiating it
— no constructor runs, no `__wakeup`/`__destruct` is triggered.

That said, JSON is *categorically* safer because no class metadata is even
parsed. Use JSON unless you have a concrete reason to use serialize.

## "Why does `getOption('key')` still return the key after `sodium_memzero`?"

The Sodium handler zeroes the **derived** key (the 32 bytes that go into
`crypto_secretbox`) before returning, but the user key — the one you passed
into the handler's options — lives in your `$options` array, which is
your buffer to manage.

If you want the user key wiped, manage that buffer yourself:

```php
$key = read_key_from_vault();
$handler = new \InitPHP\Encryption\Sodium(['key' => $key]);
// $handler now has the key inside its options array; that's the buffer
// you'll need to clear if you want it gone. Either trust the GC or
// hold a reference yourself for sodium_memzero().
$ct = $handler->encrypt($payload);
```

## "Can I use this package to encrypt files?"

For small files (anything that fits in PHP's `memory_limit` comfortably) —
yes. `encrypt(file_get_contents(...))` / `file_put_contents(..., $ct)`
works fine, but the entire file is processed as one buffer.

For large files: see "Does the package support streaming encryption?"
above.

## "Why does the README say PHP 8.1, and the composer.json says `^8.1`?"

`^8.1` means "8.1 or any later 8.x". When 9.0 comes out, this constraint
prevents the package from auto-installing — that's intentional, since 9.0
will probably have breaking language changes the package needs to verify
against. A future 2.x release will widen the constraint.

## "Where's the changelog?"

[`CHANGELOG.md`](../CHANGELOG.md) at the repository root, in
[Keep a Changelog](https://keepachangelog.com/) format.

## "I have a question that isn't here."

Open a [GitHub Discussion](https://github.com/orgs/InitPHP/discussions/categories/q-a)
in the Q&A category. If the answer turns out to be a doc gap, the question
ends up answered here in the next release.
