<?php

declare(strict_types=1);

namespace InitPHP\Encryption\Tests\Unit;

use InitPHP\Encryption\Encrypt;
use InitPHP\Encryption\Exceptions\EncryptionException;
use InitPHP\Encryption\HandlerInterface;
use InitPHP\Encryption\OpenSSL;
use InitPHP\Encryption\Tests\Fixtures\DummyHandler;
use InitPHP\Encryption\Tests\Fixtures\NotAHandler;
use PHPUnit\Framework\TestCase;

final class EncryptTest extends TestCase
{
    public function testUseInstantiatesFromClassString(): void
    {
        $handler = Encrypt::use(OpenSSL::class, ['key' => 'secret']);

        self::assertInstanceOf(OpenSSL::class, $handler);
        self::assertSame('secret', $handler->getOption('key'));
    }

    public function testUseReturnsSameInstanceWhenPassedAHandler(): void
    {
        $original = new DummyHandler(['key' => 'persistent']);
        $returned = Encrypt::use($original);

        self::assertSame($original, $returned);
    }

    public function testUseMergesOptionsIntoExistingInstance(): void
    {
        $original = new DummyHandler(['key' => 'persistent']);
        $returned = Encrypt::use($original, ['cipher' => 'AES-128-CBC']);

        self::assertSame($original, $returned);
        self::assertSame('AES-128-CBC', $returned->getOption('cipher'));
        self::assertSame('persistent', $returned->getOption('key'));
    }

    public function testUseDoesNotCallSetOptionsWhenOptionsArrayIsEmpty(): void
    {
        $original = new DummyHandler(['key' => 'persistent']);
        $snapshot = $original->getOptions();
        $returned = Encrypt::use($original, []);

        self::assertSame($snapshot, $returned->getOptions());
    }

    public function testUseThrowsOnMissingClassName(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('does not exist');

        /** @phpstan-var class-string<HandlerInterface> $missing */
        $missing = 'No\\Such\\Class\\Anywhere';
        Encrypt::use($missing);
    }

    public function testUseThrowsWhenClassDoesNotImplementHandlerInterface(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('must implement');
        $this->expectExceptionMessage(HandlerInterface::class);

        /** @phpstan-var class-string<HandlerInterface> $notHandler */
        $notHandler = NotAHandler::class;
        Encrypt::use($notHandler);
    }

    public function testUsePreservesGenericReturnTypeForExistingInstance(): void
    {
        $handler = new DummyHandler(['key' => 'k']);
        $returned = Encrypt::use($handler);

        // Confirmed at runtime: the same concrete subtype is returned.
        self::assertInstanceOf(DummyHandler::class, $returned);
    }
}
