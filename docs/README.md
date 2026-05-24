# `initphp/encryption` — Developer Documentation

This directory is the in-repo reference manual for the `initphp/encryption`
package. The top-level [README](../README.md) is the front door; everything
here is detail.

## Contents

| File | What it covers |
| --- | --- |
| [01 — Getting Started](./01-getting-started.md) | Installation, picking a handler, your first encrypt/decrypt, how to verify the install. |
| [02 — OpenSSL Handler](./02-openssl-handler.md) | OpenSSL handler internals: cipher choice, hashing algorithm, encrypt-then-MAC layout, when to pick it. |
| [03 — Sodium Handler](./03-sodium-handler.md) | Sodium handler internals: AEAD via secretbox, key derivation, padding, when to pick it. |
| [04 — Custom Handlers](./04-custom-handlers.md) | Build your own handler on top of `BaseHandler` with a worked example. |
| [05 — Options Reference](./05-options.md) | Every option, its type, default, valid values, precedence. |
| [06 — Error Handling](./06-error-handling.md) | Every failure mode, what triggers it, what a caller should do. |
| [07 — Security](./07-security.md) | Threat model, key management, what the package does and does not defend against. |
| [08 — Migration 1.x → 2.x](./08-migration-v1-to-v2.md) | What changed in 2.0 and how to re-encrypt existing data. |
| [09 — FAQ](./09-faq.md) | Common questions: hex vs base64, cookies/URLs, streaming, JSON vs serialize. |

## Suggested Reading Order

- **New to the package?** Read [01](./01-getting-started.md), then skim
  [02](./02-openssl-handler.md) or [03](./03-sodium-handler.md) depending on
  which handler you chose. Keep [05](./05-options.md) and
  [06](./06-error-handling.md) bookmarked.
- **Upgrading from 1.x?** Start with [08](./08-migration-v1-to-v2.md), then
  the README's *Upgrading* section, then [01](./01-getting-started.md) to see
  the new defaults in action.
- **Need a non-standard primitive?** [04](./04-custom-handlers.md) walks you
  through building a handler, and [07](./07-security.md) lists the contracts
  you must honour.
- **Reviewing the package for production use?** Read [07](./07-security.md)
  end-to-end, then [02](./02-openssl-handler.md) and
  [03](./03-sodium-handler.md) for the cryptographic constructions.

## Conventions in These Docs

- Every PHP code block is **verbatim runnable** against the current `src/`.
  Copy a block into a file, `require 'vendor/autoload.php'`, and it will
  produce the documented output.
- "Ciphertext" always means the hex string returned by `encrypt()`. The
  underlying bytes are described as "binary".
- The 2-byte header on every ciphertext is referred to as the *format header*;
  byte 0 is the *version byte* (always `0x02` in this release), byte 1 is the
  *serializer flag* (`0x00` = JSON, `0x01` = `php_serialize`).
- "User key" is whatever string you pass in the `key` option. "Derived key" is
  what the handler actually feeds to the cryptographic primitive after key
  derivation (HKDF for OpenSSL, BLAKE2b for Sodium).

## Reporting Issues With the Docs

Found a code sample that no longer works, an error message that doesn't match
reality, or a typo? Open an issue or a PR — doc fixes are merged eagerly. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
