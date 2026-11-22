# Error Handling

`initphp/encryption` has exactly one exception class:
`InitPHP\Encryption\Exceptions\EncryptionException`. It extends
`\RuntimeException`, so a single `try` / `catch` covers every failure
path the package can produce.

```php
use InitPHP\Encryption\Exceptions\EncryptionException;

try {
    $payload = $handler->decrypt($incoming);
} catch (EncryptionException $e) {
    // bad input, tampered ciphertext, missing key, wrong format, …
    $logger->warning('decrypt failed', ['msg' => $e->getMessage()]);
    return null;
}
```

The exception hierarchy:

```text
\Throwable
  └── \Exception
        └── \RuntimeException
              └── InitPHP\Encryption\Exceptions\EncryptionException
```

So either of these catches everything from the package:

```php
catch (\InitPHP\Encryption\Exceptions\EncryptionException $e) // most specific
catch (\RuntimeException $e)                                  // also catches everything
```

## When to Catch What

| Caller intent | Recommended `catch` | Why |
| --- | --- | --- |
| "Decrypt this; if anything is wrong, surface a generic error." | `EncryptionException` | 95% of cases. One class is enough. |
| "I want to differentiate tampering from a misconfiguration." | `EncryptionException`, then inspect `$e->getMessage()`. | The package does not subclass per failure mode; substring-match the message if you really need it. |
| "I want to retry on transient failures." | Don't. | No error here is transient. Either the input is wrong (retry won't help) or the configuration is wrong (retry won't help either). |

## Full Message Catalogue

Every message the package can produce, what triggers it, and what a caller
should do about it.

### Factory (`Encrypt::use()`)

| Message | Trigger | Caller action |
| --- | --- | --- |
| `Handler class "…" does not exist.` | Passed a string that is not a loaded class. | Programming error — fix the class name. |
| `Handler class "…" must implement InitPHP\Encryption\HandlerInterface.` | Passed an existing class that doesn't implement the interface. | Implement the interface or pass a different class. |

### Shared (raised by `BaseHandler`)

| Message | Trigger | Caller action |
| --- | --- | --- |
| `The "key" option is required and must be a non-empty string.` | `key` missing, `null`, empty, or not a string. | Set `'key' => …`. Usually a deployment/config bug. |
| `Unknown "serializer" option: ….` | `serializer` is not `json`, `php_serialize`, `php`, or `serialize`. | Use one of the supported names. |
| `Failed to JSON-encode payload: …` | Payload contains something `json_encode` rejects (non-UTF-8 binary, `NAN`, `INF`, resource). | Switch to `'serializer' => 'php_serialize'` or sanitise the payload. |
| `Failed to JSON-decode payload: …` | Ciphertext was JSON-encoded but the recovered bytes are no longer valid JSON. | Treat as corruption. |
| `Failed to unserialize the decrypted payload.` | Ciphertext was PHP-serialised but the recovered bytes are no longer parseable. | Treat as corruption. |
| `Unknown serializer flag 0x….` | Internal — only happens if a ciphertext was produced by an incompatible build. | Open an issue. |

### OpenSSL Handler

| Message | Trigger | Caller action |
| --- | --- | --- |
| `The "openssl" extension is required by the OpenSSL handler.` | `ext-openssl` is not loaded. | Install the extension or switch to Sodium. |
| `The "cipher" option is required and must be a non-empty string.` | `cipher` is missing or not a string. | Set `'cipher' => …` (default is `AES-256-CTR`). |
| `Unknown OpenSSL cipher "…".` | `cipher` is not in `openssl_get_cipher_methods()`. | Use a supported cipher. |
| `The "algo" option is required and must be a non-empty string.` | `algo` is missing or not a string. | Set `'algo' => …` (default is `SHA256`). |
| `Unknown HMAC hashing algorithm "…".` | `algo` is not in `hash_hmac_algos()`. | Use a supported algorithm. |
| `Unable to determine IV length for cipher "…".` | `openssl_cipher_iv_length()` returned `false`. Rare. | Use a different cipher. |
| `OpenSSL encryption failed: ….` | `openssl_encrypt()` returned `false`. | Inspect the included OpenSSL error message. |
| `OpenSSL decryption failed: ….` | `openssl_decrypt()` returned `false` after HMAC passed. Very unusual. | Treat as corruption. |
| `Ciphertext is not valid hex-encoded data.` | `decrypt()` input is not even-length hex. | Reject. User-supplied corruption. |
| `Ciphertext is shorter than the 2-byte header.` | Input decodes to fewer than 2 bytes. | Reject. |
| `Unsupported ciphertext format version 0x..; expected 0x02. Ciphertexts produced by 1.x are not readable by 2.x.` | Version byte ≠ `0x02`. | 1.x data (see [Migration from 1.x](Migration-from-1.x.md)) or random/corrupt input. |
| `Ciphertext is too short for the configured algorithm and cipher.` | Input lacks bytes for header + HMAC + IV. | Reject. |
| `HMAC verification failed; ciphertext is corrupted or has been tampered with.` | HMAC mismatch. | **Reject and log.** This is what tampering looks like. |

### Sodium Handler

| Message | Trigger | Caller action |
| --- | --- | --- |
| `The "sodium" extension is required by the Sodium handler.` | `ext-sodium` is not loaded. | Install the extension or switch to OpenSSL. |
| `The "blocksize" option must be a positive integer.` | `blocksize` is 0, negative, float, array, or non-numeric string. | Pass a positive integer. |
| `Sodium padding failed: ….` | `sodium_pad()` raised. Rare; usually an unreasonable block size. | Use a sane block size (16–256). |
| `Sodium unpadding failed: ….` | `sodium_unpad()` raised after MAC passed. Implies corruption. | Treat as corruption. |
| `Ciphertext is not valid hex-encoded data.` | Same as OpenSSL. | Reject. |
| `Ciphertext is too short to contain a v2 Sodium payload.` | Input decodes to fewer than 2 + nonce + MAC bytes. | Reject. |
| `Unsupported ciphertext format version 0x..; expected 0x02. Ciphertexts produced by 1.x are not readable by 2.x.` | Version byte ≠ `0x02`. | Same as OpenSSL. |
| `Sodium decryption failed; ciphertext is corrupted or has been tampered with.` | `sodium_crypto_secretbox_open()` returned `false`. | **Reject and log.** Tampering or wrong key. |

## Logging Failed Decryptions

A burst of `HMAC verification failed` / `Sodium decryption failed` from a
single source is the textbook signature of either:

- A bug in a caller that started producing corrupted ciphertexts.
- An actual attacker submitting modified or random ciphertexts.

Log enough to tell the two apart, but **do not log the offending ciphertext
itself** (it may carry sensitive data, and you don't want it growing legs
in your log indexer).

```php
try {
    return $handler->decrypt($incoming);
} catch (EncryptionException $e) {
    $logger->warning('decrypt failed', [
        'source' => $request->ip(),
        'reason' => $e->getMessage(),
        'len'    => strlen($incoming),    // bytes are safe
    ]);
    throw $e;
}
```

## Don't Show Messages to End Users

Most package messages would help an attacker tune their input. Map every
`EncryptionException` to a generic user-facing message and put the detail
in the server log only.

```php
try {
    return $handler->decrypt($incoming);
} catch (EncryptionException) {
    http_response_code(400);
    exit('Invalid request');
}
```

## See Also

- [Configuration Options](Configuration-Options.md) — every option and the
  validation that goes with it.
- [Security Best Practices](Security-Best-Practices.md) — how to think about
  the attacker model behind these errors.
- [Migration from 1.x](Migration-from-1.x.md) — what to do when you see
  `Unsupported ciphertext format version` in production.
- [Troubleshooting](Troubleshooting.md) — diagnostic checklists for the
  common cases.
