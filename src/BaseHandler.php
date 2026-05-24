<?php

declare(strict_types=1);

namespace InitPHP\Encryption;

use InitPHP\Encryption\Exceptions\EncryptionException;
use JsonException;

/**
 * Shared option handling and payload (de)serialization for every concrete
 * handler. Subclasses focus on the cryptographic primitive; this class owns
 * the configuration surface and the boundary between PHP values and bytes.
 *
 * @phpstan-type EncryptionOptions array{
 *     algo?: string,
 *     cipher?: string,
 *     key?: string|null,
 *     blocksize?: int|string,
 *     serializer?: string,
 * }
 */
abstract class BaseHandler implements HandlerInterface
{
    /**
     * Magic byte placed at the start of every ciphertext produced by a 2.x
     * handler. Decryption refuses any value with a different version byte,
     * which is how this release rejects v1 ciphertexts.
     */
    public const FORMAT_VERSION = 0x02;

    /**
     * JSON serialization. Default. Safe against object-injection attacks
     * because no PHP class is ever instantiated during decoding.
     */
    public const SERIALIZER_JSON = 'json';

    /**
     * PHP's native serialize()/unserialize() pair. Opt-in because
     * unserialize() can instantiate arbitrary classes when allowed_classes
     * is not constrained. This handler always passes
     * ['allowed_classes' => false], so payloads round-trip stdClass
     * (and scalars/arrays) but custom classes degrade to __PHP_Incomplete_Class.
     */
    public const SERIALIZER_PHP = 'php_serialize';

    protected const SERIALIZER_FLAG_JSON = 0x00;
    protected const SERIALIZER_FLAG_PHP = 0x01;

    /**
     * @var array<string, mixed>
     *
     * @phpstan-var EncryptionOptions
     */
    protected array $options = [
        'algo' => 'SHA256',
        'cipher' => 'AES-256-CTR',
        'key' => null,
        'blocksize' => 16,
        'serializer' => self::SERIALIZER_JSON,
    ];

    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     */
    public function __construct(array $options = [])
    {
        $this->setOptions($options);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     */
    public function setOptions(array $options = []): static
    {
        if ($options === []) {
            return $this;
        }
        /** @phpstan-var EncryptionOptions $merged */
        $merged = array_merge($this->options, array_change_key_case($options, CASE_LOWER));
        $this->options = $merged;

        return $this;
    }

    public function setOption(string $name, mixed $value): static
    {
        $this->options[strtolower($name)] = $value;

        return $this;
    }

    public function getOption(string $name, mixed $default = null): mixed
    {
        return $this->options[strtolower($name)] ?? $default;
    }

    /**
     * @return array<string, mixed>
     *
     * @phpstan-return EncryptionOptions
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Produce a fresh option array merged from the persistent options and a
     * per-call override. The returned array is always a copy: subclasses may
     * mutate or {@see sodium_memzero()} it without affecting handler state.
     *
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     *
     * @return array<string, mixed>
     *
     * @phpstan-return EncryptionOptions
     */
    protected function resolveOptions(array $options = []): array
    {
        if ($options === []) {
            return $this->options;
        }

        /** @phpstan-var EncryptionOptions $merged */
        $merged = array_merge($this->options, array_change_key_case($options, CASE_LOWER));

        return $merged;
    }

    /**
     * Read and validate the 'key' option. Returns the key as a non-empty
     * string or throws — handlers never have to second-guess key presence.
     *
     * @param array<string, mixed> $options
     *
     * @throws EncryptionException
     */
    protected function requireKey(array $options): string
    {
        $key = $options['key'] ?? null;
        if (!\is_string($key) || $key === '') {
            throw new EncryptionException('The "key" option is required and must be a non-empty string.');
        }

        return $key;
    }

    /**
     * Resolve the configured serializer name to its on-wire flag byte.
     *
     * @param array<string, mixed> $options
     *
     * @throws EncryptionException
     */
    protected function serializerFlag(array $options): int
    {
        $name = strtolower((string) ($options['serializer'] ?? self::SERIALIZER_JSON));

        return match ($name) {
            self::SERIALIZER_JSON, 'json' => self::SERIALIZER_FLAG_JSON,
            self::SERIALIZER_PHP, 'php', 'serialize' => self::SERIALIZER_FLAG_PHP,
            default => throw new EncryptionException(\sprintf('Unknown "serializer" option: %s.', $name)),
        };
    }

    /**
     * Encode a payload according to the resolved serializer flag.
     *
     * @throws EncryptionException
     */
    protected function serializePayload(mixed $data, int $flag): string
    {
        return match ($flag) {
            self::SERIALIZER_FLAG_JSON => $this->jsonEncode($data),
            self::SERIALIZER_FLAG_PHP => serialize($data),
            default => throw new EncryptionException(\sprintf('Unknown serializer flag 0x%02x.', $flag)),
        };
    }

    /**
     * Decode a payload according to the serializer flag read from the
     * ciphertext header. PHP-serialized payloads are decoded with
     * allowed_classes:false to neutralise object-injection attempts.
     *
     * @throws EncryptionException
     */
    protected function unserializePayload(string $data, int $flag): mixed
    {
        switch ($flag) {
            case self::SERIALIZER_FLAG_JSON:
                return $this->jsonDecode($data);
            case self::SERIALIZER_FLAG_PHP:
                $value = @unserialize($data, ['allowed_classes' => false]);
                if ($value === false && $data !== serialize(false)) {
                    throw new EncryptionException('Failed to unserialize the decrypted payload.');
                }

                return $value;
            default:
                throw new EncryptionException(\sprintf('Unknown serializer flag 0x%02x.', $flag));
        }
    }

    private function jsonEncode(mixed $data): string
    {
        try {
            return json_encode(
                $data,
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
            );
        } catch (JsonException $e) {
            throw new EncryptionException('Failed to JSON-encode payload: ' . $e->getMessage(), 0, $e);
        }
    }

    private function jsonDecode(string $data): mixed
    {
        try {
            return json_decode($data, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new EncryptionException('Failed to JSON-decode payload: ' . $e->getMessage(), 0, $e);
        }
    }
}
