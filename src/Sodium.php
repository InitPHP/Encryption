<?php
/**
 * Sodium.php
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

use const SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
use const SODIUM_CRYPTO_SECRETBOX_MACBYTES;

use function extension_loaded;
use function bin2hex;
use function hex2bin;
use function serialize;
use function unserialize;
use function random_bytes;
use function mb_strlen;
use function sodium_pad;
use function sodium_crypto_secretbox;
use function sodium_memzero;
use function sodium_crypto_secretbox_open;
use function sodium_unpad;

class Sodium extends BaseHandler implements HandlerInterface
{

    public function __construct(array $options = [])
    {
        if(extension_loaded('sodium') === FALSE){
            throw new \InitPHP\Encryption\Exceptions\EncryptionException('The "sodium" extension must be installed.');
        }
        parent::__construct($options);
    }

    /**
     * @param $data
     * @param array $options
     * @return string
     * @throws \SodiumException
     * @throws \Exception
     */
    public function encrypt($data, array $options = []): string
    {
        $options = $this->options($options);
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $data = serialize($data);
        $data = sodium_pad($data, (int)$options['blocksize']);
        $ciphertext = $nonce . sodium_crypto_secretbox($data, $nonce, $options['key']);
        sodium_memzero($data);
        sodium_memzero($options['key']);
        return bin2hex($ciphertext);
    }

    /**
     * @param $data
     * @param array $options
     * @return mixed
     * @throws EncryptionException
     * @throws \SodiumException
     */
    public function decrypt($data, array $options = [])
    {
        $options = $this->options($options);
        $data = hex2bin($data);
        if(mb_strlen($data, '8bit') < (SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES)){
            throw new EncryptionException('Decryption failed!');
        }
        $nonce = $this->substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = $this->substr($data, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        if(($data = sodium_crypto_secretbox_open($ciphertext, $nonce, $options['key'])) === FALSE){
            throw new EncryptionException('Decryption failed!');
        }
        $data = sodium_unpad($data, $options['blocksize']);
        sodium_memzero($ciphertext);
        sodium_memzero($options['key']);
        return unserialize($data);
    }

}
