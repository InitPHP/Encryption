# Recipes

Cookbook-style snippets for the patterns that come up most often. Every
example assumes:

```php
require __DIR__ . '/vendor/autoload.php';

use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\Exceptions\EncryptionException;
use InitPHP\Encryption\Sodium;
```

All snippets are written against the Sodium handler for brevity; the
OpenSSL handler is a drop-in replacement.

## 1. Encrypted Session Cookie

Encrypt a session payload, set it as a cookie, decrypt on the next
request.

```php
function setSessionCookie(string $name, array $payload, string $key): void
{
    $handler = Encrypt::use(Sodium::class, ['key' => $key]);
    setcookie($name, $handler->encrypt($payload), [
        'httponly' => true,
        'secure'   => true,
        'samesite' => 'Strict',
        'path'     => '/',
        'expires'  => time() + 86400,
    ]);
}

function readSessionCookie(string $name, string $key): ?array
{
    if (empty($_COOKIE[$name])) {
        return null;
    }
    try {
        $payload = Encrypt::use(Sodium::class, ['key' => $key])
            ->decrypt($_COOKIE[$name]);
        return is_array($payload) ? $payload : null;
    } catch (EncryptionException) {
        // tampered or stale cookie — treat as no session
        return null;
    }
}

// Usage:
setSessionCookie('app_session', ['user_id' => 42], getenv('APP_KEY'));
$payload = readSessionCookie('app_session', getenv('APP_KEY'));
```

The `try` / `catch` is the important bit — a tampered cookie should
silently drop you back to "no session" rather than surface a server error.

## 2. Encrypted Database Column

Transparently encrypt a column on write, decrypt on read. Example with
PDO:

```php
function persistUserNote(PDO $db, int $userId, string $note, string $key): void
{
    $handler = Encrypt::use(Sodium::class, ['key' => $key]);
    $stmt = $db->prepare(
        'INSERT INTO user_notes (user_id, body, created_at)
         VALUES (:uid, :body, NOW())'
    );
    $stmt->execute([
        ':uid'  => $userId,
        ':body' => $handler->encrypt($note),
    ]);
}

function readUserNotes(PDO $db, int $userId, string $key): array
{
    $handler = Encrypt::use(Sodium::class, ['key' => $key]);
    $stmt = $db->prepare('SELECT id, body FROM user_notes WHERE user_id = :uid');
    $stmt->execute([':uid' => $userId]);

    $out = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        try {
            $out[] = ['id' => (int) $row['id'], 'note' => $handler->decrypt($row['body'])];
        } catch (EncryptionException) {
            $out[] = ['id' => (int) $row['id'], 'note' => null, 'error' => 'unreadable'];
        }
    }
    return $out;
}
```

The column should be `TEXT` (or `VARCHAR(8192)` with a generous size).
Hex doubles the byte size, so a 200-byte note becomes a ~500-character
column value.

## 3. Encrypted URL Token

Round-trip a small payload in a URL. Hex is URL-safe by default — no
percent-escaping needed.

```php
function tokenFor(array $payload, string $key): string
{
    return Encrypt::use(Sodium::class, ['key' => $key])->encrypt($payload);
}

function payloadFrom(string $token, string $key): ?array
{
    try {
        $result = Encrypt::use(Sodium::class, ['key' => $key])->decrypt($token);
        return is_array($result) ? $result : null;
    } catch (EncryptionException) {
        return null;
    }
}

// Usage:
$token = tokenFor(['reset_uid' => 42, 'exp' => time() + 3600], getenv('APP_KEY'));
echo "https://example.com/reset?t={$token}\n";

// On the receiving side:
$payload = payloadFrom($_GET['t'] ?? '', getenv('APP_KEY'));
if ($payload === null || ($payload['exp'] ?? 0) < time()) {
    http_response_code(400);
    exit('Invalid or expired token');
}
```

Expiry is enforced by *you*, not the package — it has no notion of "this
ciphertext expires at time X". Embed an `exp` field in the payload and
check it on read.

## 4. Encrypted File On Disk

Encrypt small files (anything that fits comfortably in `memory_limit`).

```php
function encryptToFile(string $sourcePath, string $destPath, string $key): void
{
    $contents  = file_get_contents($sourcePath);
    if ($contents === false) {
        throw new RuntimeException("Cannot read {$sourcePath}");
    }
    // Use php_serialize so raw binary bytes survive:
    $handler   = Encrypt::use(Sodium::class, [
        'key'        => $key,
        'serializer' => 'php_serialize',
    ]);
    file_put_contents($destPath, $handler->encrypt($contents));
}

function decryptFromFile(string $sourcePath, string $destPath, string $key): void
{
    $ciphertext = file_get_contents($sourcePath);
    if ($ciphertext === false) {
        throw new RuntimeException("Cannot read {$sourcePath}");
    }
    $handler = Encrypt::use(Sodium::class, [
        'key'        => $key,
        'serializer' => 'php_serialize',
    ]);
    file_put_contents($destPath, $handler->decrypt($ciphertext));
}
```

For large files (gigabytes), this is the wrong tool — see the
[FAQ](FAQ.md#does-the-package-support-streaming-encryption) for the right
primitive (`crypto_secretstream_xchacha20poly1305_*` via a custom
handler).

## 5. Multi-Tenant Encryption

Different tenants, different keys, same handler class.

```php
final class TenantCrypto
{
    /** @var array<int, \InitPHP\Encryption\HandlerInterface> */
    private array $handlers = [];

    public function __construct(private \Closure $keyForTenant) {}

    private function handler(int $tenantId): \InitPHP\Encryption\HandlerInterface
    {
        return $this->handlers[$tenantId] ??= Encrypt::use(Sodium::class, [
            'key' => ($this->keyForTenant)($tenantId),
        ]);
    }

    public function encrypt(int $tenantId, mixed $value): string
    {
        return $this->handler($tenantId)->encrypt($value);
    }

    public function decrypt(int $tenantId, string $ciphertext): mixed
    {
        return $this->handler($tenantId)->decrypt($ciphertext);
    }
}

// Bootstrap:
$crypto = new TenantCrypto(fn (int $tid) => fetchTenantKeyFromVault($tid));
$ct = $crypto->encrypt(42, ['secret' => 'top']);
$pt = $crypto->decrypt(42, $ct);
```

Handler instances are cached per tenant so the key derivation runs once
per tenant per process, not per encrypt call.

## 6. Key Rotation With Fallback Decrypt

Read with the new key first, fall back to the old key transparently. As
soon as you re-write the value, it migrates to the new key.

```php
function decryptWithRotation(
    string $ciphertext,
    string $newKey,
    ?string $oldKey,
): mixed {
    try {
        return (new Sodium(['key' => $newKey]))->decrypt($ciphertext);
    } catch (EncryptionException) {
        if ($oldKey === null || $oldKey === '') {
            throw new RuntimeException('decrypt failed and no fallback key available');
        }
        return (new Sodium(['key' => $oldKey]))->decrypt($ciphertext);
    }
}

// Migration job: re-encrypt under the new key.
$writer = new Sodium(['key' => $newKey = getenv('APP_KEY')]);
foreach (yieldStoredCiphertexts() as $row) {
    $plain = decryptWithRotation($row->ciphertext, $newKey, getenv('APP_KEY_PREVIOUS'));
    $row->ciphertext = $writer->encrypt($plain);
    $row->save();
}
```

Once every stored ciphertext has been re-encrypted, drop
`APP_KEY_PREVIOUS` from your secret store and remove the fallback code.

## 7. Encrypting an HTTP Response Body

Useful for "envelope-encrypted webhook" patterns.

```php
function emitEncryptedJson(array $payload, string $key): never
{
    header('Content-Type: application/octet-stream');
    $handler = Encrypt::use(Sodium::class, ['key' => $key]);
    echo $handler->encrypt($payload);
    exit;
}

function ingestEncryptedJson(string $key): array
{
    $body = file_get_contents('php://input') ?: '';
    try {
        $payload = Encrypt::use(Sodium::class, ['key' => $key])->decrypt($body);
    } catch (EncryptionException) {
        http_response_code(400);
        exit('Invalid envelope');
    }
    if (!is_array($payload)) {
        http_response_code(400);
        exit('Bad payload type');
    }
    return $payload;
}
```

Both sides agree on the key out-of-band (env var, shared secret manager).
Tamper resistance comes from the package's authenticated encryption.

## See Also

- [Sodium Handler](Sodium-Handler.md) / [OpenSSL Handler](OpenSSL-Handler.md) —
  pick the right handler.
- [Security Best Practices](Security-Best-Practices.md) — key management for
  the patterns above.
- [Error Handling](Error-Handling.md) — what to catch in those `try` blocks.
- [Testing Your Encryption](Testing-Your-Encryption.md) — how to test these
  patterns in your own suite.
