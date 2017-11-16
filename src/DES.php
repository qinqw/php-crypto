<?php
/**
 * Provides an easy and secure way to encrypt/decrypt data with PHP 
 * using the Symmetric Cryptography method.(DES,3DES,OPENSSL) 
 * bootstrap
 * 
 * @category PHP_Crypto
 * @package  Qinqw\Crypto
 * @author   Kevin <qinqiwei@hotmail.com>
 * @license  Apache License V2
 * @link     https://github.com/qinqw/php-crypto
 */
namespace Qinqw\Crypto;

class DES
{
    /**
     * des-cbc加密
     * @param string  $data 要被加密的数据
     * @param string  $key 加密使用的key
     */
    public static function encrypt($data, $key=null)
    {
        if(strlen($key)!=8)
        {
            $key='x#a-y6nl';
        }
        $cipher = 'des-cbc';
        $ivlen = openssl_cipher_iv_length($cipher);
        $iv = $key;
        $options = 0;
        return openssl_encrypt($data, $cipher, $key, $options, $iv);
    }

    /**
     * des-cbc解密
     * @param string  $data 加密数据
     * @param string  $key 加密使用的key
     */
    public static function decrypt($data, $key=null)
    {
        if(strlen($key)!=8)
        {
            $key='x#a-y6nl';
        }
        $cipher = 'des-cbc';
        $ivlen = openssl_cipher_iv_length($cipher);
        $iv = $key;
        $options = 0;
        return openssl_decrypt($data, $cipher, $key, $options, $iv);
    }
}