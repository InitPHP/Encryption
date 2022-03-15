<?php
/**
 * Encrypt.php
 *
 * This file is part of InitPHP.
 *
 * @author     Muhammet ŞAFAK <info@muhammetsafak.com.tr>
 * @copyright  Copyright © 2022 InitPHP
 * @license    http://initphp.github.io/license.txt  MIT
 * @version    1.0
 * @link       https://www.muhammetsafak.com.tr
 */

declare(strict_types=1);

namespace InitPHP\Encryption;

use \InitPHP\Encryption\Exceptions\EncryptionException;

use function is_string;
use function class_exists;

class Encrypt
{

    /**
     * @param string|HandlerInterface $handler
     * @param array $options
     * @return HandlerInterface
     * @throws EncryptionException
     */
    public static function use($handler, array $options = []): HandlerInterface
    {
        if(is_string($handler) && class_exists($handler)){
            $handler = new $handler($options);
            $options = null;
        }
        if(!($handler instanceof HandlerInterface)){
            throw new EncryptionException('');
        }
        return empty($options) ? $handler : $handler->setOptions($options);
    }

    /**
     * @param string|HandlerInterface $handler
     * @param array $options
     * @return HandlerInterface
     * @throws EncryptionException
     */
    public static function create($handler, array $options = []): HandlerInterface
    {
        return self::use($handler, $options);
    }


}
