# Error Handling

`initphp/encryption` has exactly one exception class:
`InitPHP\Encryption\Exceptions\EncryptionException`. It extends
`\RuntimeException`, so a single `try` / `catch` covers every failure path.

```php
use InitPHP\Encryption\Exceptions\EncryptionException;

try {
    $plaintext = $handler->decrypt($incoming);
} catch (EncryptionException $e) {
    // handle, log, surface — but DO NOT echo $e->getMessage() to end users.
    $logger->warning('decryption failed', ['msg' => $e->getMessage()]);
    return null;
}
```

## When to Catch What

| Caller intent | What to catch | Why |
| --- | --- | --- |
| "Decrypt this; if anything is wrong, the user gets a generic error." | `EncryptionException` | This is 95% of cases. The single class is enough. |
| "I want to differentiate tampering from server misconfiguration." | `EncryptionException`, inspect `getMessage()` against the table below. | The package does not currently subclass `EncryptionException` per failure mode. Substring-match on the message if you really need to. |
| "I want to retry on transient errors." | Don't. | No error in this package is transient. Either the input is wrong (retry won't help) or the configuration is wrong (retry won't help). |

## Catalogue of Error Messages

Every message the package can produce, what triggers it, and what a caller
should do about it.

### Factory (`Encrypt::use()`)

| Message | Trigger | Caller action |
| --- | --- | --- |
| `Handler class "…" does not exist.` | Passed a string that is not a loaded class. | Fix the class name; this is a programming error. |
| `Handler class "…" must implement InitPHP\Encryption\HandlerInterface.` | Passed a class that exists but doesn't implement the interface. | Either implement the interface or pass a different class. |

### Common (raised by `BaseHandler`)

| Message | Trigger | Caller action |
| --- | --- | --- |
| `The "key" option is required and must be a non-empty string.` | `key` option missing, `null`, empty string, or not a string. | Set `'key' => …` to a real secret. Most likely a deployment/config bug. |
| `Unknown "serializer" option: ….` | `serializer` is not one of `json`, `php_serialize`, `php`, `serialize`. | Use one of the supported names. See [05 — Options](./05-options.md). |
| `Unknown serializer flag 0x….` | Internal — should never happen unless your ciphertext was produced by an incompatible build. | Open an issue. |
| `Failed to JSON-encode payload: …` | Payload contains a value `json_encode` rejects (NaN, INF, non-UTF-8 binary, resource). | Switch to `'serializer' => 'php_serialize'` or sanitise the payload. |
| `Failed to JSON-decode payload: …` | Ciphertext was JSON-serialized but the bytes are no longer valid JSON. | Means tampering or corruption — treat like a decrypt failure. |
| `Failed to unserialize the decrypted payload.` | Ciphertext was PHP-serialized but the bytes are no longer parseable. | Same — likely corruption. |

### OpenSSL Handler

| Message | Trigger | Caller action |
| --- | --- | --- |
| `The "openssl" extension is required by the OpenSSL handler.` | `ext-openssl` is not loaded. | Install the extension or switch to the Sodium handler. |
| `The "cipher" option is required and must be a non-empty string.` | `cipher` option is missing or not a string. | Set `'cipher' => …` (default is `AES-256-CTR`). |
| `Unknown OpenSSL cipher "…".` | `cipher` is not in `openssl_get_cipher_methods()`. | Use a supported cipher name. |
| `The "algo" option is required and must be a non-empty string.` | `algo` is missing or not a string. | Set `'algo' => …` (default is `SHA256`). |
| `Unknown HMAC hashing algorithm "…".` | `algo` is not in `hash_hmac_algos()`. | Use a supported hash name. |
| `Unable to determine IV length for cipher "…".` | `openssl_cipher_iv_length()` returned `false`. Rare; usually means the cipher name is valid but the build doesn't support it. | Pick a different cipher. |
| `OpenSSL encryption failed: ….` | `openssl_encrypt()` returned `false`. Includes the OpenSSL error string when available. | Investigate the included message; usually a cipher/IV mismatch. |
| `OpenSSL decryption failed: ….` | `openssl_decrypt()` returned `false` after HMAC passed (extremely unlikely). | Treat as corruption. |
| `Ciphertext is not valid hex-encoded data.` | `decrypt()` input is not even-length hex. | Reject input — user-supplied corruption. |
| `Ciphertext is shorter than the 2-byte header.` | Input decodes to fewer than 2 bytes. | Reject input. |
| `Unsupported ciphertext format version 0x..; expected 0x02. Ciphertexts produced by 1.x are not readable by 2.x.` | Version byte ≠ `0x02`. | Either 1.x data (see [migration guide](./08-migration-v1-to-v2.md)) or random/corrupt input. |
| `Ciphertext is too short for the configured algorithm and cipher.` | Input doesn't have enough bytes for the header + HMAC + IV. | Reject input. |
| `HMAC verification failed; ciphertext is corrupted or has been tampered with.` | The HMAC computed from the wire doesn't match the one stored. | **Reject and log.** This is what tampering looks like. |

### Sodium Handler

| Message | Trigger | Caller action |
| --- | --- | --- |
| `The "sodium" extension is required by the Sodium handler.` | `ext-sodium` is not loaded. | Install the extension or switch to OpenSSL. |
| `The "blocksize" option must be a positive integer.` | `blocksize` is `0`, negative, non-integer (other than digit string), or non-numeric. | Use a positive integer. |
| `Sodium padding failed: ….` | `sodium_pad()` raised a `SodiumException`. Rare; usually means the block size is unreasonable (e.g. `PHP_INT_MAX`). | Use a sane block size (16–256). |
| `Sodium unpadding failed: ….` | `sodium_unpad()` raised — the decrypted bytes are not properly padded. Implies corruption since the MAC already passed. | Treat as corruption. |
| `Ciphertext is not valid hex-encoded data.` | Same as OpenSSL. | Reject input. |
| `Ciphertext is too short to contain a v2 Sodium payload.` | Input decodes to fewer than 2 + nonce + MAC bytes. | Reject input. |
| `Unsupported ciphertext format version 0x..; expected 0x02. Ciphertexts produced by 1.x are not readable by 2.x.` | Version byte ≠ `0x02`. | Same as OpenSSL. |
| `Sodium decryption failed; ciphertext is corrupted or has been tampered with.` | `sodium_crypto_secretbox_open()` returned `false`. | **Reject and log.** This is what tampering or wrong-key looks like. |

## Logging Failed Decryptions

A repeated burst of `HMAC verification failed` / `Sodium decryption failed`
from one source is the textbook signature of either:

- A serialisation bug in a caller that started corrupting ciphertexts.
- An actual attacker trying random or modified ciphertexts.

Log enough to tell the two apart (source identifier, count over time) — but
do not log the offending ciphertext itself (it may contain secrets if the
attacker is testing exfiltration). The exception message is safe.

```php
try {
    $handler->decrypt($incoming);
} catch (EncryptionException $e) {
    $logger->warning('decrypt failed', [
        'source' => $request->ip(),
        'reason' => $e->getMessage(),
    ]);
}
```

## Don't Show Messages to End Users

Most messages here would help an attacker tune their input. Map every
`EncryptionException` to a generic user-facing message and put the detail in
the server log only.

```php
try {
    return $handler->decrypt($incoming);
} catch (EncryptionException) {
    return response('Invalid request', 400);
}
```

## See Also

- [05 — Options Reference](./05-options.md) — every option, every validation
  rule.
- [07 — Security](./07-security.md) — how to think about the attacker model.
- [08 — Migration 1.x → 2.x](./08-migration-v1-to-v2.md) — what to do when
  you see the `Unsupported ciphertext format version` message in production.
