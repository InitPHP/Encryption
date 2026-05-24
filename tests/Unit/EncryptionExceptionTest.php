<?php

declare(strict_types=1);

namespace InitPHP\Encryption\Tests\Unit;

use Exception;
use InitPHP\Encryption\Exceptions\EncryptionException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class EncryptionExceptionTest extends TestCase
{
    public function testExtendsRuntimeException(): void
    {
        $exception = new EncryptionException('boom');

        self::assertInstanceOf(RuntimeException::class, $exception);
    }

    public function testIsCatchableAsRuntimeException(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('boom');

        throw new EncryptionException('boom');
    }

    public function testIsCatchableAsBaseException(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('boom');

        throw new EncryptionException('boom');
    }

    public function testCarriesPreviousException(): void
    {
        $previous = new RuntimeException('root cause');
        $exception = new EncryptionException('wrapper', 0, $previous);

        self::assertSame($previous, $exception->getPrevious());
    }
}
