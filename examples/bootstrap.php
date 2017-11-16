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

spl_autoload_register( 
    function ($class) {
        // project-specific namespace prefix
        $prefix = 'Qinqw\\Crypto';

        // base directory for the namespace prefix
        $base_dir = dirname(__DIR__) . '/src/';

        // does the class use the namespace prefix?
        $len = strlen($prefix);
        if (strncmp($prefix, $class, $len) !== 0) {
            // no, move to the next registered autoloader
            return;
        }

        // get the relative class name
        $relative_class = substr($class, $len);

        // replace the namespace prefix with the base directory, replace namespace
        // separators with directory separators in the relative class name, append
        // with .php
        $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

        // if the file exists, require it
        if (file_exists($file)) {
            //require $file;
            include $file;
        }
    }
);
