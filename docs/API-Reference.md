# API Reference

Complete list of every public class member exposed by the package, with
signatures and a one-line description.

For deeper explanations, follow the cross-references to the handler-specific
pages.

## Namespace Map

```text
InitPHP\Encryption\
├── Encrypt                              ← factory
├── HandlerInterface                     ← contract
├── BaseHandler                          ← abstract base (extend this)
├── OpenSSL                              ← final concrete handler
├── Sodium                               ← final concrete handler
└── Exceptions\
    └── EncryptionException              ← the only thrown type
```

## `InitPHP\Encryption\Encrypt`

`final class Encrypt`

Convenience factory.

### `Encrypt::use()`

```php
public static function use(
    string|HandlerInterface $handler,
    array $options = []
): HandlerInterface
```

Instantiates a handler from a class name (passing `$options` to its
constructor), or returns the given instance (merging `$options` via
`setOptions`).

- `$handler` — either a fully-qualified class name that implements
  `HandlerInterface`, or an already-constructed handler instance.
- `$options` — option overrides; case-insensitive keys.

Throws `EncryptionException` if the string is not a loaded class, or the
resulting object does not implement `HandlerInterface`.

Generic typing (`@template T of HandlerInterface`) preserves the concrete
handler type at static-analysis time.

```php
$handler = Encrypt::use(\InitPHP\Encryption\Sodium::class, ['key' => 'k']);
// PHPStan infers $handler : Sodium
```

## `InitPHP\Encryption\HandlerInterface`

`interface HandlerInterface`

The contract every handler must implement.

### `encrypt()`

```php
public function encrypt(mixed $data, array $options = []): string;
```

Encrypts `$data` and returns the hex-encoded ciphertext. Per-call options
are merged on top of the handler's persistent ones and do not mutate state.

### `decrypt()`

```php
public function decrypt(string $data, array $options = []): mixed;
```

Decrypts a ciphertext previously returned by `encrypt()` on the same
handler class (and compatible options).

### `setOptions()`

```php
public function setOptions(array $options = []): static;
```

Merges options into the handler's persistent state. Returns the concrete
handler type (`static`) for fluent chaining.

## `InitPHP\Encryption\BaseHandler`

`abstract class BaseHandler implements HandlerInterface`

Shared option management + payload serialization. Extend this when writing
a custom handler — see [Custom Handlers](Custom-Handlers.md).

### Constants

```php
public const FORMAT_VERSION       = 0x02;
public const SERIALIZER_JSON      = 'json';
public const SERIALIZER_PHP       = 'php_serialize';

protected const SERIALIZER_FLAG_JSON = 0x00;
protected const SERIALIZER_FLAG_PHP  = 0x01;
```

`FORMAT_VERSION` is the magic byte that opens every ciphertext.
`SERIALIZER_JSON` / `SERIALIZER_PHP` are the public string values for the
`serializer` option. The flag-byte constants are protected (internal
wire-format detail).

### Constructor

```php
public function __construct(array $options = []);
```

### Public methods (in addition to the interface)

```php
public function setOption(string $name, mixed $value): static;
public function getOption(string $name, mixed $default = null): mixed;
public function getOptions(): array;
```

Read/write individual options. Keys are case-insensitive.

### Protected helpers (for subclasses)

```php
protected function resolveOptions(array $options = []): array;
protected function requireKey(array $options): string;
protected function serializerFlag(array $options): int;
protected function serializePayload(mixed $data, int $flag): string;
protected function unserializePayload(string $data, int $flag): mixed;
```

See [Custom Handlers](Custom-Handlers.md) for what each does and how to use
them.

### Default options

```php
protected array $options = [
    'algo'       => 'SHA256',
    'cipher'     => 'AES-256-CTR',
    'key'        => null,
    'blocksize'  => 16,
    'serializer' => self::SERIALIZER_JSON,
];
```

## `InitPHP\Encryption\OpenSSL`

`final class OpenSSL extends BaseHandler`

`encrypt-then-MAC` handler built on `ext-openssl` and `hash_hmac`.

### Constructor

```php
public function __construct(array $options = []);
```

Throws `EncryptionException` if `ext-openssl` is not loaded.

Inherits every method from `BaseHandler`. Recognised options: `key`,
`cipher`, `algo`, `serializer`.

See [OpenSSL Handler](OpenSSL-Handler.md) for the full reference.

## `InitPHP\Encryption\Sodium`

`final class Sodium extends BaseHandler`

AEAD handler built on `ext-sodium`'s `crypto_secretbox`.

### Constructor

```php
public function __construct(array $options = []);
```

Throws `EncryptionException` if `ext-sodium` is not loaded.

Inherits every method from `BaseHandler`. Recognised options: `key`,
`blocksize`, `serializer`.

See [Sodium Handler](Sodium-Handler.md) for the full reference.

## `InitPHP\Encryption\Exceptions\EncryptionException`

```php
class EncryptionException extends \RuntimeException
{
}
```

The only exception type the package raises. Carries a `previous` exception
when wrapping underlying causes (`SodiumException`, `JsonException`).

See [Error Handling](Error-Handling.md) for every message and what triggers
it.

## Type Annotations (PHPStan)

`BaseHandler` exports a `@phpstan-type` alias other classes can import:

```php
/**
 * @phpstan-type EncryptionOptions array{
 *     algo?: string,
 *     cipher?: string,
 *     key?: string|null,
 *     blocksize?: int|string,
 *     serializer?: string,
 * }
 */
```

In a custom handler:

```php
/**
 * @phpstan-import-type EncryptionOptions from \InitPHP\Encryption\BaseHandler
 */
final class MyHandler extends \InitPHP\Encryption\BaseHandler
{
    /**
     * @phpstan-param EncryptionOptions $options
     */
    public function encrypt(mixed $data, array $options = []): string { /* … */ }
}
```

## Composer Metadata

Relevant subset of `composer.json`:

```json
{
    "name": "initphp/encryption",
    "type": "library",
    "license": "MIT",
    "require":  { "php": "^8.2" },
    "suggest":  {
        "ext-openssl": "Required by the OpenSSL handler.",
        "ext-sodium":  "Required by the Sodium handler."
    },
    "autoload": {
        "psr-4": { "InitPHP\\Encryption\\": "src/" }
    }
}
```

Composer scripts (dev only): `composer test`, `composer phpstan`,
`composer cs-check`, `composer cs-fix`, `composer qa`.

## See Also

- [Configuration Options](Configuration-Options.md) — option-by-option
  reference.
- [Custom Handlers](Custom-Handlers.md) — extending `BaseHandler`.
- [Error Handling](Error-Handling.md) — exception catalogue.
