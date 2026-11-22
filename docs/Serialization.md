# Serialization

`encrypt()` accepts `mixed` and `decrypt()` returns `mixed`. Between the two,
the handler runs your payload through a serializer chosen via the
`serializer` option. The chosen serializer is recorded in the ciphertext
header, so `decrypt()` always restores the original type — even if you
change the option between calls.

## Choices

| Option value | Flag byte | Library calls | When to use |
| --- | :---: | --- | --- |
| `'json'` (default), `'JSON'` | `0x00` | `json_encode` / `json_decode` with `JSON_THROW_ON_ERROR` | Most cases. Scalars, arrays, `stdClass`. Safe — no PHP class is ever instantiated during decoding. |
| `'php_serialize'`, `'php'`, `'serialize'`, `'SERIALIZE'` | `0x01` | `serialize()` / `unserialize($_, ['allowed_classes' => false])` | 8-bit-clean payloads (raw binary), or you have a deep object graph that JSON cannot round-trip. |

The constants:

```php
use InitPHP\Encryption\BaseHandler;

BaseHandler::SERIALIZER_JSON; // 'json'
BaseHandler::SERIALIZER_PHP;  // 'php_serialize'
```

Use the named constants in production code; the string aliases exist for
ergonomics.

## Why JSON by Default?

`unserialize()` on attacker-controlled bytes is the canonical PHP
object-injection vector. The package's authentication does mean an attacker
without the key can't put bytes into your `unserialize()` call — but
defense in depth is cheap, so the default is the safer one.

JSON cannot instantiate classes at all. There is no gadget-chain attack
surface even if the key leaks.

## Picking PHP Serialize

Switch to `'serializer' => 'php_serialize'` if any of these apply:

- Your payload contains **raw binary bytes** (image data, encrypted
  sub-payloads, `random_bytes()` output). JSON is not 8-bit-clean.
- You round-trip **`stdClass` instances** and care about preserving the
  exact type (JSON decodes to an associative array unless you ask for
  `JSON_OBJECT_AS_OBJECT`, which the handler does not pass).
- You round-trip **custom classes** and only need them as
  `__PHP_Incomplete_Class` on the decode side (the `allowed_classes:
  false` constraint always applies).

Even with `php_serialize`, the package always passes `['allowed_classes'
=> false]` to `unserialize`. Custom classes survive the encode side but
come back as `__PHP_Incomplete_Class` instances — no `__wakeup` /
`__destruct` ever runs.

## Examples

### Scalars round-trip identically

```php
use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\Sodium;

$h = Encrypt::use(Sodium::class, ['key' => 'k']);

$h->decrypt($h->encrypt('hello'));    // → 'hello'
$h->decrypt($h->encrypt(42));         // → 42
$h->decrypt($h->encrypt(3.14));       // → 3.14
$h->decrypt($h->encrypt(true));       // → true
$h->decrypt($h->encrypt(false));      // → false
$h->decrypt($h->encrypt(null));       // → null
```

### Arrays round-trip

```php
use InitPHP\Encryption\Sodium;

$h = new Sodium(['key' => 'k']);
$ct = $h->encrypt(['x' => 1, 'y' => ['nested' => [1, 2, 3]]]);
$pt = $h->decrypt($ct);
// $pt === ['x' => 1, 'y' => ['nested' => [1, 2, 3]]]
```

### Binary needs `php_serialize`

```php
use InitPHP\Encryption\Sodium;
use InitPHP\Encryption\Exceptions\EncryptionException;

$h = new Sodium(['key' => 'k', 'serializer' => 'php_serialize']);
$binary = "\x00\x01\x02\xff some raw bytes";
$ct = $h->encrypt($binary);
echo bin2hex($h->decrypt($ct)) === bin2hex($binary)
    ? "ok\n" : "lost bytes\n";
// → ok

// Same payload under JSON throws on encode:
$json = new Sodium(['key' => 'k', 'serializer' => 'json']);
try {
    $json->encrypt("\xB1\xC2\xD3");
} catch (EncryptionException $e) {
    echo $e->getMessage(), PHP_EOL;
    // → Failed to JSON-encode payload: Malformed UTF-8 characters, possibly incorrectly encoded
}
```

### Custom objects degrade safely on PHP serialize

```php
use InitPHP\Encryption\Sodium;

class User { public function __construct(public string $name) {} }

$h  = new Sodium(['key' => 'k', 'serializer' => 'php_serialize']);
$ct = $h->encrypt(new User('alice'));
$pt = $h->decrypt($ct);

// $pt is __PHP_Incomplete_Class — no User constructor runs.
echo get_class($pt), PHP_EOL;
// → __PHP_Incomplete_Class

// Access via casts:
echo ((array) $pt)["\0+\0name"] ?? 'n/a', PHP_EOL;
// → alice (the property survived, but the class identity did not)
```

If you need real object round-tripping, JSON-serialise the object's data
yourself and reconstruct on the read side:

```php
$ct = $h->encrypt(['type' => 'User', 'name' => 'alice']);
$pt = $h->decrypt($ct);
$user = match ($pt['type']) {
    'User' => new User($pt['name']),
    default => throw new InvalidArgumentException('unknown type'),
};
```

## What `decrypt()` Does With the Flag

The serializer flag is byte 1 of the format header. `decrypt()` reads it
before doing any deserialisation work:

```php
match ($flag) {
    BaseHandler::SERIALIZER_FLAG_JSON => json_decode($data, true, 512, JSON_THROW_ON_ERROR),
    BaseHandler::SERIALIZER_FLAG_PHP  => unserialize($data, ['allowed_classes' => false]),
    default => throw new EncryptionException('Unknown serializer flag 0x..'),
};
```

(The exact flag byte values are implementation detail; they are not part
of the public API.)

Because the flag travels with the ciphertext, you can change the handler's
`serializer` option between encrypt and decrypt without losing data —
the encrypt-time choice always wins on decode.

## Trade-Offs Summary

| Concern | JSON | PHP serialize |
| --- | :---: | :---: |
| Safe against gadget-chain RCE | ✅ (no classes ever loaded) | ✅ (via `allowed_classes: false`) |
| Round-trips scalars | ✅ | ✅ |
| Round-trips arrays | ✅ | ✅ |
| Round-trips raw binary | ❌ (UTF-8 only) | ✅ |
| Round-trips `stdClass` as object | ❌ (decodes to array) | ✅ |
| Round-trips custom classes | ❌ | ⚠️ (returns `__PHP_Incomplete_Class`) |
| Ciphertext size (small payloads) | comparable | comparable |
| Speed | very fast | very fast |

For 95% of use cases, the default JSON is the right answer.

## See Also

- [Configuration Options](Configuration-Options.md) — how to set the
  `serializer` option.
- [Ciphertext Format](Ciphertext-Format.md) — where the serializer flag lives
  on the wire.
- [Security Best Practices](Security-Best-Practices.md) — why
  `unserialize()` on attacker bytes is the historical worry.
