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

/**
 * RSA
 * 
 * @category PHP_Crypto
 * @package  Qinqw\Crypto
 * @author   Kevin <qinqiwei@hotmail.com>
 * @license  Apache License V2
 * @link     https://github.com/qinqw/php-crypto
 */
class RSA
{

    private $_privateKey = null;
    private $_publicKey = null;

    /**
     * __construct
     *
     * @param mixed $publicKey  共钥
     * @param mixed $privateKey 私钥
     *
     * @return mixed 
     */
    function __construct($publicKey, $privateKey)
    {
        $this->_publicKey = $publicKey;
        $this->_privateKey = $privateKey;
    }

    /**
     * 私钥加密
     *
     * @param string $data 要加密的数据
     *
     * @return string 加密后的字符串
     */
    public function privateKeyEncode($data)
    {
        $encrypted = '';
        $this->_needKey(2);
        $private_key = openssl_pkey_get_private($this->_privateKey);
        $fstr = array();
        $array_data = $this->_splitEncode($data);//把要加密的信息 base64 encode后 等长放入数组
        foreach ($array_data as $value) {//理论上是可以只加密数组中的第一个元素 其他的不加密 因为只要一个解密不出来 整体也就解密不出来 这里先全部加密
            openssl_private_encrypt($value, $encrypted, $private_key); //私钥加密
            $fstr[] = $encrypted;//对数组中每个加密
        }
        return base64_encode(serialize($fstr));//序列化后base64_encode
    }

    /**
     * 公钥加密
     *
     * @param string $data 要加密的数据
     *
     * @return string 加密后的字符串
     */
    public function publicKeyEncode($data)
    {
        $encrypted = '';
        $this->_needKey(1);
        $public_key = openssl_pkey_get_public($this->_publicKey);
        $fstr = array();
        $array_data = $this->_splitEncode($data);
        foreach ($array_data as $value) {
            openssl_public_encrypt($value, $encrypted, $public_key); //私钥加密
            $fstr[] = $encrypted;
        }
        return base64_encode(serialize($fstr));
    }

    /**
     * 用公钥解密私钥加密内容
     *
     * @param string $data 要解密的数据
     *
     * @return string 解密后的字符串
     */
    public function decodePrivateEncode($data)
    {
        $decrypted = '';
        $this->_needKey(1);
        $public_key = openssl_pkey_get_public($this->_publicKey);
        $array_data = $this->_toArray($data);//数据base64_decode 后 反序列化成数组
        $str = '';
        foreach ($array_data as $value) {
               openssl_public_decrypt($value, $decrypted, $public_key); //私钥加密的内容通过公钥可用解密出来
               $str .= $decrypted;//对数组中的每个元素解密 并拼接
        }
        return base64_decode($str);//把拼接的数据base64_decode 解密还原
    }

    /**
     * 用私钥解密公钥加密内容
     *
     * @param string $data 要解密的数据
     *
     * @return string 解密后的字符串
     */
    public function decodePublicEncode($data)
    {
        $decrypted = '';
        $this->_needKey(2);
        $private_key = openssl_pkey_get_private($this->_privateKey);
        $array_data = $this->_toArray($data);
        $str = '';
        foreach ($array_data as $value) {
               openssl_private_decrypt($value, $decrypted, $private_key); //私钥解密
               $str .= $decrypted;
        }
        return base64_decode($str);
    }

    /**
     * 检查是否 含有所需配置文件
     *
     * @param int $type 1 公钥 2 私钥
     * 
     * @return int 1
     * @throws Exception
     */
    private function _needKey($type)
    {
        switch ($type) {
        case 1:
            if (empty($this->_publicKey)) {
                throw new Exception('请配置公钥');
            }
            break;
        case 2:
            if (empty($this->_privateKey)) {
                throw new Exception('请配置私钥');
            }
            break;
        }
        return 1;
    }

    /**
     * Split Encode
     *
     * @param type $data Date
     *
     * @return type
     */
    private function _splitEncode($data)
    {
        $data = base64_encode($data); //加上base_64 encode  便于用于 分组
        $total_lenth = strlen($data);
        $per = 96;// 能整除2 和 3 RSA每次加密不能超过100个
        $dy = $total_lenth % $per;
        $total_block = $dy ? ($total_lenth / $per) : ($total_lenth / $per - 1);
        for ($i = 0; $i < $total_block; $i++) {
            $return[] = substr($data, $i * $per, $per);//把要加密的信息base64 后 按64长分组
        }
        return $return;
    }
    
    /**
     * 公钥加密并用 base64 serialize 过的 data
     *
     * @param type $data base64 serialize 过的 data
     * 
     * @return mixed
     */
    private  function _toArray($data)
    {
        $data = base64_decode($data);
        $array_data = unserialize($data);
        if (!is_array($array_data)) {
            throw new Exception('数据加密不符');
        }
        return $array_data;
    }

}