<?php
/**
 * Provides an easy and secure way to encrypt/decrypt data with PHP 
 * using the Symmetric Cryptography method.(DES,3DES,OPENSSL) 
 * 
 * @category PHP_Crypto
 * @package  Qinqw\Crypto
 * @author   Kevin <qinqiwei@hotmail.com>
 * @license  Apache License V2
 * @link     https://github.com/qinqw/php-crypto
 */

require 'bootstrap.php';
use Qinqw\Crypto\DES;

$key = 'qinqiwei';
$plaintext = 'aaaaaallllll';

$encrypt =DES::encrypt($plaintext,$key);
var_dump($encrypt);


$decrypt = DES::decrypt($encrypt,$key);

var_dump($decrypt);

$encrypt= 'igCw5Heuc1M=';
$decrypt = DES::decrypt($encrypt);
var_dump($decrypt);

// $ciphers_and_aliases = openssl_get_cipher_methods(true);
// var_dump($ciphers_and_aliases);