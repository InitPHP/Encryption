# Testing Your Encryption

Encryption code is uniquely easy to get *almost* right and uniquely easy
to never find out. A small set of property-style tests catches the
mistakes that lead to silent data loss or to wrongly-trusted ciphertexts.

This page gives you a battery of tests modelled after the package's own
suite. Drop them into your project's PHPUnit setup, adapt the handler
construction to your bootstrap, and you have a regression net for
whatever uses encryption.

## Test Battery — Mandatory

These tests should exist for every handler instance you use in
production.

### 1. Round-trip

The plaintext that goes in must come back out, unchanged:

```php
public function testRoundTripPreservesValue(): void
{
    $handler = $this->handlerUnderTest();

    foreach ($this->payloadFixtures() as $label => $value) {
        $ciphertext = $handler->encrypt($value);
        $roundtrip  = $handler->decrypt($ciphertext);

        self::assertSame($value, $roundtrip, "round-trip failed for {$label}");
    }
}

private function payloadFixtures(): iterable
{
    yield 'string' => 'hello';
    yield 'int'    => 42;
    yield 'array'  => ['x' => 1, 'y' => [1, 2, 3]];
    yield 'null'   => null;
    yield 'bool'   => true;
}
```

If you use `'serializer' => 'php_serialize'` in your handler, add a
binary case:

```php
yield 'binary' => "\x00\x01\xff raw bytes";
```

JSON cannot round-trip raw binary — that test belongs only on the
`php_serialize` configuration.

### 2. Ciphertexts differ across calls

Same plaintext, same handler — different ciphertext. If two calls return
the same hex string, your IV / nonce randomisation is broken:

```php
public function testCiphertextDiffersAcrossCalls(): void
{
    $handler = $this->handlerUnderTest();
    $a = $handler->encrypt('same plaintext');
    $b = $handler->encrypt('same plaintext');

    self::assertNotSame($a, $b);
}
```

### 3. Tampering is rejected

Flip a single byte. The handler must throw, not return garbage:

```php
public function testDecryptRejectsTamperedCiphertext(): void
{
    $handler = $this->handlerUnderTest();
    $ct = $handler->encrypt('hello');

    // Flip one hex character (= flip 4 bits of the underlying binary):
    $tampered = $ct;
    $tampered[-1] = $ct[-1] === '0' ? '1' : '0';

    $this->expectException(\InitPHP\Encryption\Exceptions\EncryptionException::class);

    $handler->decrypt($tampered);
}
```

### 4. Wrong key cannot decrypt

```php
public function testWrongKeyCannotDecrypt(): void
{
    $writer = new \InitPHP\Encryption\Sodium(['key' => 'key-a']);
    $reader = new \InitPHP\Encryption\Sodium(['key' => 'key-b']);
    $ct = $writer->encrypt('hello');

    $this->expectException(\InitPHP\Encryption\Exceptions\EncryptionException::class);

    $reader->decrypt($ct);
}
```

### 5. Non-hex / truncated input is rejected

```php
public function testDecryptRejectsNonHex(): void
{
    $this->expectException(\InitPHP\Encryption\Exceptions\EncryptionException::class);
    $this->handlerUnderTest()->decrypt('not-hex-at-all-zzz');
}

public function testDecryptRejectsTruncated(): void
{
    $this->expectException(\InitPHP\Encryption\Exceptions\EncryptionException::class);
    $this->handlerUnderTest()->decrypt('ab'); // 1 binary byte, < header
}
```

### 6. Wrong format version is rejected

If a 1.x ciphertext ever ends up in your store, decryption must fail
loudly, not silently:

```php
public function testDecryptRejectsWrongVersionByte(): void
{
    $handler = $this->handlerUnderTest();
    $ct = $handler->encrypt('hello');

    // Replace the version byte (first hex pair) with something else:
    $forged = '01' . substr($ct, 2);

    $this->expectException(\InitPHP\Encryption\Exceptions\EncryptionException::class);
    $this->expectExceptionMessage('Unsupported ciphertext format version');

    $handler->decrypt($forged);
}
```

### 7. Per-call options don't mutate handler state

A subtle correctness invariant — if a per-call override leaked into the
handler, two unrelated callers would step on each other:

```php
public function testPerCallOptionsDoNotMutateHandlerState(): void
{
    $handler = new \InitPHP\Encryption\OpenSSL([
        'key'    => 'k',
        'cipher' => 'AES-256-CTR',
    ]);

    $handler->encrypt('x', ['cipher' => 'AES-128-CTR']);

    self::assertSame('AES-256-CTR', $handler->getOption('cipher'));
}
```

## Test Battery — Recommended

### 8. Configuration errors raise the right exception

```php
public function testMissingKeyRaisesEncryptionException(): void
{
    $handler = new \InitPHP\Encryption\Sodium();

    $this->expectException(\InitPHP\Encryption\Exceptions\EncryptionException::class);
    $this->expectExceptionMessage('"key"');

    $handler->encrypt('hello');
}
```

### 9. Format header is what you expect

Useful when you are writing a custom handler or asserting compatibility
guarantees in integration tests:

```php
public function testCiphertextStartsWithFormatVersionByte(): void
{
    $ct = $this->handlerUnderTest()->encrypt('hello');
    $firstByte = hexdec(substr($ct, 0, 2));

    self::assertSame(
        \InitPHP\Encryption\BaseHandler::FORMAT_VERSION,
        $firstByte
    );
}
```

### 10. JSON-vs-PHP serializer flag is recorded

```php
public function testSerializerFlagMatchesConfiguredSerializer(): void
{
    $json = new \InitPHP\Encryption\Sodium(['key' => 'k']); // default = json
    $php  = new \InitPHP\Encryption\Sodium([
        'key'        => 'k',
        'serializer' => 'php_serialize',
    ]);

    self::assertSame(0x00, hexdec(substr($json->encrypt('x'), 2, 2)));
    self::assertSame(0x01, hexdec(substr($php->encrypt('x'),  2, 2)));
}
```

## Test Fixtures

If you need to test a `BaseHandler` subclass without depending on a real
cryptographic extension, use the same trick the package's own suite uses:
a `DummyHandler` that re-exposes the protected helpers.

```php
namespace App\Tests\Fixtures;

use InitPHP\Encryption\BaseHandler;

final class DummyHandler extends BaseHandler
{
    public function encrypt(mixed $data, array $options = []): string
    {
        $flag = $this->serializerFlag($this->resolveOptions($options));

        return $this->serializePayload($data, $flag);
    }

    public function decrypt(string $data, array $options = []): mixed
    {
        $flag = $this->serializerFlag($this->resolveOptions($options));

        return $this->unserializePayload($data, $flag);
    }

    public function callRequireKey(array $options): string
    {
        return $this->requireKey($options);
    }

    // ... add `callX()` wrappers for every protected helper you need.
}
```

## What Not to Test

- **The cryptographic primitives themselves.** Don't write tests that
  assert specific ciphertext bytes for a fixed plaintext + key. Random
  IV/nonce makes that impossible, and even if you turned that off you
  would be testing OpenSSL / libsodium rather than your code.
- **Speed.** Performance regressions matter, but benchmark them in a
  separate script — PHPUnit timing is too noisy to fail builds on.
- **Memory zeroing.** PHP makes it impossible to assert "this byte is
  really gone from process memory" from user code. Trust the library.

## CI Tips

- Run your encryption tests on **every supported PHP version**. PHP minor
  releases occasionally change `unserialize` or `hash_*` behaviour.
- Run them with **`failOnWarning="true"`** and **`failOnDeprecation="true"`**
  in PHPUnit (this is what the package's own suite uses). A deprecation
  notice in a crypto path is something you want to see immediately, not
  in a year.
- Consider running the suite under PHPStan or Psalm. The package ships
  with full type annotations; static analysis catches "I passed an array
  where a string was expected" before runtime does.

## See Also

- [Error Handling](Error-Handling.md) — the full catalogue of messages your
  tests can assert against.
- [Custom Handlers](Custom-Handlers.md) — the protected helpers the fixture
  above re-exposes.
- [Recipes](Recipes.md) — patterns to write integration tests for.
