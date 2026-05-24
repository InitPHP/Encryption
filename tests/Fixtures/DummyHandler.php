<?php

declare(strict_types=1);

namespace InitPHP\Encryption\Tests\Fixtures;

use InitPHP\Encryption\BaseHandler;

/**
 * Minimal concrete handler used to drive {@see BaseHandler} from unit tests
 * without depending on the openssl or sodium extensions. The cryptographic
 * operations are stubbed; only the option and serialization machinery is real.
 *
 * Protected helpers are re-exposed as public methods so tests can assert on
 * them directly.
 */
final class DummyHandler extends BaseHandler
{
    public function encrypt(mixed $data, array $options = []): string
    {
        $resolved = $this->resolveOptions($options);
        $flag = $this->serializerFlag($resolved);

        return $this->serializePayload($data, $flag);
    }

    public function decrypt(string $data, array $options = []): mixed
    {
        $resolved = $this->resolveOptions($options);
        $flag = $this->serializerFlag($resolved);

        return $this->unserializePayload($data, $flag);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function callRequireKey(array $options): string
    {
        return $this->requireKey($options);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function callSerializerFlag(array $options): int
    {
        return $this->serializerFlag($options);
    }

    public function callSerializePayload(mixed $data, int $flag): string
    {
        return $this->serializePayload($data, $flag);
    }

    public function callUnserializePayload(string $data, int $flag): mixed
    {
        return $this->unserializePayload($data, $flag);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array<string, mixed>
     */
    public function callResolveOptions(array $options): array
    {
        return $this->resolveOptions($options);
    }

    public function jsonFlag(): int
    {
        return self::SERIALIZER_FLAG_JSON;
    }

    public function phpFlag(): int
    {
        return self::SERIALIZER_FLAG_PHP;
    }
}
