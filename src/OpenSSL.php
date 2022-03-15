<?php
/**
 * OpenSSL.php
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

use const OPENSSL_RAW_DATA;

use function extension_loaded;
use function serialize;
use function unserialize;
use function bin2hex;
use function hex2bin;
use function openssl_encrypt;
use function openssl_decrypt;
use function openssl_cipher_iv_length;
use function openssl_random_pseudo_bytes;
use function hash_hkdf;
use function hash_hmac;
use function hash_equals;

class OpenSSL extends BaseHandler implements HandlerInterface
{

    public function __construct(array $options = [])
    {
        if(extension_loaded('openssl') === FALSE){
            throw new \InitPHP\Encryption\Exceptions\EncryptionException('The "openssl" extension must be installed.');
        }
        parent::__construct($options);
    }

    public function encrypt($data, array $options = []): string
    {
        $options = $this->options($options);

        $secret = hash_hkdf($options['algo'], $options['key']);
        $iv = ($IVSize = openssl_cipher_iv_length($options['cipher'])) ? openssl_random_pseudo_bytes($IVSize) : null;
        $data = serialize($data);

        if(($data = openssl_encrypt($data, $options['cipher'], $secret, OPENSSL_RAW_DATA, $iv)) === FALSE){
            throw new \InitPHP\Encryption\Exceptions\EncryptionException('Encryption failed.');
        }
        $res = $iv . $data;
        $hmac = hash_hmac($options['algo'], $res, $secret, true);
        return bin2hex($hmac . $res);
    }

    public function decrypt($data, array $options = [])
    {
        $options = $this->options($options);
        $data = hex2bin($data);
        $secret = hash_hkdf($options['algo'], $options['key']);

        $hmacLength = $this->substr($options['algo'], 3) / 8;
        $hmacKey = $this->substr($data, 0, $hmacLength);
        $data = $this->substr($data, $hmacLength);
        $hmacCalc = hash_hmac($options['algo'], $data, $secret, true);
        if(hash_equals($hmacKey, $hmacCalc) === FALSE){
            throw new \InitPHP\Encryption\Exceptions\EncryptionException('Decryption verification failed.');
        }
        $iv = ($ivSize = openssl_cipher_iv_length($options['cipher'])) ? $this->substr($data, 0, $ivSize) : null;
        if($iv !== null){
            $data = $this->substr($data, $ivSize);
        }
        $data = openssl_decrypt($data, $options['cipher'], $secret, OPENSSL_RAW_DATA, $iv);
        return unserialize($data);
    }

}
