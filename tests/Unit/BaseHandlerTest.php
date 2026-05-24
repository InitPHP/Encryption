<?php

declare(strict_types=1);

namespace InitPHP\Encryption\Tests\Unit;

use InitPHP\Encryption\BaseHandler;
use InitPHP\Encryption\Exceptions\EncryptionException;
use InitPHP\Encryption\Tests\Fixtures\DummyHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

final class BaseHandlerTest extends TestCase
{
    public function testConstructMergesGivenOptionsOverDefaults(): void
    {
        $handler = new DummyHandler(['cipher' => 'AES-128-CTR']);

        self::assertSame('AES-128-CTR', $handler->getOption('cipher'));
        self::assertSame('SHA256', $handler->getOption('algo'), 'default kept for keys not overridden');
    }

    public function testSetOptionsReturnsSameInstanceForFluentChaining(): void
    {
        $handler = new DummyHandler();
        $result = $handler->setOptions(['key' => 'k']);

        self::assertSame($handler, $result);
    }

    public function testSetOptionsReturnsStaticInstanceShortCircuitsOnEmpty(): void
    {
        $handler = new DummyHandler(['key' => 'k']);
        $before = $handler->getOptions();

        $handler->setOptions([]);

        self::assertSame($before, $handler->getOptions());
    }

    public function testSetOptionLowercasesKey(): void
    {
        $handler = new DummyHandler();
        $handler->setOption('CIPHER', 'AES-128-CBC');

        self::assertSame('AES-128-CBC', $handler->getOption('cipher'));
        self::assertSame('AES-128-CBC', $handler->getOption('CiPhEr'));
    }

    public function testSetOptionsIsCaseInsensitive(): void
    {
        $handler = new DummyHandler();
        $handler->setOptions(['CIPHER' => 'AES-128-CBC', 'Algo' => 'sha512']);

        self::assertSame('AES-128-CBC', $handler->getOption('cipher'));
        self::assertSame('sha512', $handler->getOption('algo'));
    }

    public function testGetOptionReturnsProvidedDefaultForMissingKey(): void
    {
        $handler = new DummyHandler();

        self::assertSame('fallback', $handler->getOption('nope', 'fallback'));
    }

    public function testGetOptionsExposesDefaults(): void
    {
        $handler = new DummyHandler();
        $options = $handler->getOptions();

        self::assertArrayHasKey('algo', $options);
        self::assertArrayHasKey('cipher', $options);
        self::assertArrayHasKey('key', $options);
        self::assertArrayHasKey('blocksize', $options);
        self::assertArrayHasKey('serializer', $options);
        self::assertSame(BaseHandler::SERIALIZER_JSON, $handler->getOption('serializer'));
    }

    public function testResolveOptionsDoesNotMutateHandlerState(): void
    {
        $handler = new DummyHandler(['key' => 'persistent']);
        $resolved = $handler->callResolveOptions(['key' => 'override', 'cipher' => 'AES-128-CTR']);

        self::assertSame('override', $resolved['key']);
        self::assertSame('AES-128-CTR', $resolved['cipher']);
        self::assertSame('persistent', $handler->getOption('key'), 'handler state must be preserved');
    }

    public function testRequireKeyThrowsWhenKeyIsMissing(): void
    {
        $handler = new DummyHandler();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('"key"');

        $handler->callRequireKey($handler->getOptions());
    }

    public function testRequireKeyThrowsWhenKeyIsEmptyString(): void
    {
        $handler = new DummyHandler(['key' => '']);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('"key"');

        $handler->callRequireKey($handler->getOptions());
    }

    public function testRequireKeyThrowsWhenKeyIsNotString(): void
    {
        $handler = new DummyHandler();

        $this->expectException(EncryptionException::class);

        // Bypass the property type-juggling by setting via setOption (which casts the name only).
        $handler->callRequireKey(['key' => 12345]);
    }

    public function testRequireKeyReturnsNonEmptyString(): void
    {
        $handler = new DummyHandler(['key' => 'top-secret']);

        self::assertSame('top-secret', $handler->callRequireKey($handler->getOptions()));
    }

    /**
     * @return array<string, array{0: string, 1: int}>
     */
    public static function serializerAliasProvider(): array
    {
        return [
            'json (canonical)' => [BaseHandler::SERIALIZER_JSON, 0x00],
            'json (uppercase)' => ['JSON', 0x00],
            'php_serialize (canonical)' => [BaseHandler::SERIALIZER_PHP, 0x01],
            'php (alias)' => ['php', 0x01],
            'serialize (alias)' => ['serialize', 0x01],
            'SERIALIZE (mixed case)' => ['SERIALIZE', 0x01],
        ];
    }

    #[DataProvider('serializerAliasProvider')]
    public function testSerializerFlagResolvesNamesAndAliases(string $name, int $expectedFlag): void
    {
        $handler = new DummyHandler();

        self::assertSame($expectedFlag, $handler->callSerializerFlag(['serializer' => $name]));
    }

    public function testSerializerFlagDefaultsToJson(): void
    {
        $handler = new DummyHandler();

        self::assertSame($handler->jsonFlag(), $handler->callSerializerFlag([]));
    }

    public function testSerializerFlagThrowsOnUnknownName(): void
    {
        $handler = new DummyHandler();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unknown "serializer" option');

        $handler->callSerializerFlag(['serializer' => 'msgpack']);
    }

    public function testSerializePayloadJson(): void
    {
        $handler = new DummyHandler();
        $encoded = $handler->callSerializePayload(['a' => 1], $handler->jsonFlag());

        self::assertSame('{"a":1}', $encoded);
    }

    public function testSerializePayloadJsonRespectsUnicode(): void
    {
        $handler = new DummyHandler();
        $encoded = $handler->callSerializePayload(['msg' => 'çığ'], $handler->jsonFlag());

        self::assertSame('{"msg":"çığ"}', $encoded);
    }

    public function testSerializePayloadJsonThrowsOnUnsupportedValue(): void
    {
        $handler = new DummyHandler();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('JSON-encode');

        // A non-UTF-8 byte sequence cannot be JSON-encoded.
        $handler->callSerializePayload("\xB1\xC2\xD3", $handler->jsonFlag());
    }

    public function testSerializePayloadPhpHandlesObjects(): void
    {
        $handler = new DummyHandler();
        $object = new stdClass();
        $object->name = 'phpunit';

        $encoded = $handler->callSerializePayload($object, $handler->phpFlag());

        self::assertSame(serialize($object), $encoded);
    }

    public function testSerializePayloadThrowsOnUnknownFlag(): void
    {
        $handler = new DummyHandler();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unknown serializer flag');

        $handler->callSerializePayload('x', 0xFF);
    }

    public function testUnserializePayloadJson(): void
    {
        $handler = new DummyHandler();

        self::assertSame(['a' => 1], $handler->callUnserializePayload('{"a":1}', $handler->jsonFlag()));
    }

    public function testUnserializePayloadJsonThrowsOnInvalidJson(): void
    {
        $handler = new DummyHandler();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('JSON-decode');

        $handler->callUnserializePayload('not-json', $handler->jsonFlag());
    }

    public function testUnserializePayloadPhpReturnsScalarsAndArrays(): void
    {
        $handler = new DummyHandler();
        $payload = serialize(['x' => 1, 'y' => [2, 3]]);

        self::assertSame(['x' => 1, 'y' => [2, 3]], $handler->callUnserializePayload($payload, $handler->phpFlag()));
    }

    public function testUnserializePayloadPhpReturnsFalseLiteral(): void
    {
        $handler = new DummyHandler();
        $payload = serialize(false);

        self::assertFalse($handler->callUnserializePayload($payload, $handler->phpFlag()));
    }

    public function testUnserializePayloadPhpRefusesCustomObjectsViaAllowedClassesFalse(): void
    {
        $handler = new DummyHandler();
        $object = new stdClass();
        $object->level = 42;
        $payload = serialize($object);

        $decoded = $handler->callUnserializePayload($payload, $handler->phpFlag());

        self::assertInstanceOf('__PHP_Incomplete_Class', $decoded);
    }

    public function testUnserializePayloadPhpThrowsOnGarbledInput(): void
    {
        $handler = new DummyHandler();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('unserialize');

        $handler->callUnserializePayload('not-a-serialized-value', $handler->phpFlag());
    }

    public function testUnserializePayloadThrowsOnUnknownFlag(): void
    {
        $handler = new DummyHandler();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unknown serializer flag');

        $handler->callUnserializePayload('x', 0xFF);
    }
}
