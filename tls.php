<?php

/**
 * TLS 1.2 decoding proof of concept.
 *
 * Note:
 *   - PHP does not do 64bit packet. Sequence number is limited to 32bits
 *   - Only limited to TLS_RSA_WITH_RC4_128_SHA
 *   - Don't use mcrypt ARCFOUR, or probably any other RC4 library, as state MUST be preserved between calls
 *   - Pre-master-secret, random values and encrypted data taken from wireshark and SSLKEYLOGFILE (google it).
 *   - If you use something from this code for any other reason than curiosity, you're nuts...
 */

// Pre master secret
$pre_master_secret = hex2bin("03034f855727c944e11c5d74490ce62b550db46a96b32a7be76d68342dcc7fe9c87026090ebb99245f3ffd13f9ed185a");

// Client and server random values
$client_random = hex2bin("52c14c28f2e0af0f3f02228be4b79e0475ba987902f47fce67d2a58a778d5f6a");
$server_random = hex2bin("52c14c298bf57e252efc0835a685b875bb9670e7ab2293e03b78381e046de736");

$tls = new TLS($pre_master_secret, $client_random, $server_random);

$bytes = hex2bin("9e8e681ce6407984d7f0966d770e06180c81682fb2c553288f655b2c242bbc6dbf208ec9");
$tls->decrypt(TLS::SIDE_CLIENT, TLS::CONTENT_TYPE_HANDSHAKE, $bytes);
print "Encrypted handshake data from client is ok\n";

$bytes = hex2bin("8ed128fc47354243242d621242b06a42eb964e14f354da70bd54b12191b26bd76b993b64");
$tls->decrypt(TLS::SIDE_SERVER, TLS::CONTENT_TYPE_HANDSHAKE, $bytes);
print "Encrypted handshake data from client is ok\n";

$bytes = hex2bin("31dd7439f2922fca00419902b1689c4a2ddef9fa17ff01282cc09edf3872d8dec17f6b261a5ab108a268352f3907a09c8800828553bf8cb2bec0856bcd35dd51398410abb1d9ca6d23f0e61499e6520f30744a5a40919a3ef4f7461abe7a535e5bb0c378ec7530963e0b40c142dcf18519e9a09af341163037ed6a6cae0a6763cd626fb7589594865bd0cb8e6998cc66cc1e6add90c8dbd0d7eae5d122a2ea7190b65872ed3adadee41ab442f70cba2e01f66ebb315b7c763d3596a888ae70a5997a4157d296e6d07b717839c229e9fb6f9ac7adc8a86464b9892ac0541314003f22bc61b815d3d5cb525d4c002a387cdb22bed0f201b718601d5fdb12f6dabb2c40e86692d37cd12ad5241acde41beb189b321fe41f554cbe3613f4b51d23bc8ef64dc33f09f48a5b2b3e1add5c1467b9c52cbf7b2bdeee1c6ac3ee0487443aa989c7b2e17685c8524c7bfe9ff0d72edd5cb19da4db20d30e17ad9b13759f25ed1d4a285acee3d769c1ba15302d906143820915496bacfd940cae9d295383b4645bc1c6967885ec0a6fc0c8423e70e8bbbe8038e375b0737daac620b883ae07e67535b27bd8b8b6e342880b268b5d61dd1131d6167bbae14fc581708b52df224f7f17d7f69fd987f25e1f59470bee35cc6487783103313668db15480483e57412d113fa91d19d7d0730c7e3771da7d9fe940fc8e34f66729f0ae806bb30d8631b9699576f86172921ac57adc7634e9507ebc2c88c742ee645e79c411267793f425b4d6c2da5e9f3bd7ed58dcb0371280bac6765cbb645a107b02d9584f224");
$http_req = $tls->decrypt(TLS::SIDE_CLIENT, TLS::CONTENT_TYPE_APPLICATION_DATA, $bytes);
print "First HTTP request: \n";
print $http_req;
exit;



class TLS {
    const SIDE_CLIENT = 'client';
    const SIDE_SERVER = 'server';

    const CONTENT_TYPE_HANDSHAKE = 22;
    const CONTENT_TYPE_APPLICATION_DATA = 23;

    protected $sides = array();

    protected $master_secret = null;

    /**
     *
     */
    function __construct($pre_master_secret, $client_random, $server_random) {
        $this->master_secret = $this->generate_master($pre_master_secret, $client_random, $server_random);

        // Create client_write_keys, macs and ivs
        list ($cwm, $swm, $cwk, $swk, $cwi, $swi) = $this->generate_keys($this->master_secret, $client_random, $server_random);

        // Create our client and server data structures
        $this->sides[self::SIDE_CLIENT] = array();
        $this->sides[self::SIDE_CLIENT]['cipher'] = new RC4($cwk);
        $this->sides[self::SIDE_CLIENT]['mac'] = hash_init("sha1", HASH_HMAC, $cwm);
        $this->sides[self::SIDE_CLIENT]['seq'] = 0;

        $this->sides[self::SIDE_SERVER] = array();
        $this->sides[self::SIDE_SERVER]['cipher'] = new RC4($swk);
        $this->sides[self::SIDE_SERVER]['mac'] = hash_init("sha1", HASH_HMAC, $swm);
        $this->sides[self::SIDE_SERVER]['seq'] = 0;
    }


    /**
     *
     */
    protected function generate_keys($master_secret, $client_random, $server_random) {
        // TLS_RSA_WITH_RC4_128_SHA has 20byte mac + 16byte key means 72 bytes of data is needed
        $key_buffer = $this->prf_tls12($master_secret, 'key expansion', $server_random . $client_random, 72);

        $result = array();
        $result[] = substr($key_buffer, 0, 20);
        $result[] = substr($key_buffer, 20, 20);

        $result[] = substr($key_buffer, 40, 16);
        $result[] = substr($key_buffer, 56, 16);

        $result[] = "";
        $result[] = "";
        return $result;
    }


    /**
     *
     */
    function decrypt($side, $content_type, $bytes) {
        $plaintext = $this->sides[$side]['cipher']->decrypt($bytes);

        $mac = substr($plaintext, -20, 20);
        $msg = substr($plaintext, 0, -20);
        if (! $this->verify_mac($this->sides[$side]['seq']++, $content_type, $msg, $mac, $this->sides[$side]['mac'])) {
            throw new \DomainException('MAC verification failed');
        }

        return $msg;
    }


    /**
     *
     */
    protected function verify_mac($seq, $content_type, $msg, $original_mac, $hmac) {
        $data = pack("NN", 0, $seq) . pack("Cnn", $content_type, 0x0303, strlen($msg)) . $msg;

        $hmac_copy = hash_copy($hmac);
        hash_update($hmac_copy, $data);
        $calculated_mac = hash_final($hmac_copy, true);

        return ($original_mac == $calculated_mac);
    }


    /**
     *
     */
    protected function generate_master($pre_master_secret, $client_random, $server_random) {
        return $this->prf_tls12($pre_master_secret, 'master secret', $client_random. $server_random, 48);
    }


    /**
     *
     */
    protected function prf_tls12($secret, $label, $seed, $size = 48) {
        return $this->p_hash("sha256", $secret, $label . $seed, $size);
    }


    /**
     *
     */
    protected function p_hash($algo, $secret, $seed, $size) {
        $output = "";
        $a = $seed;

        while (strlen($output) < $size) {
            $a = hash_hmac($algo, $a, $secret, true);
            $output .= hash_hmac($algo, $a . $seed, $secret, true);
        }

        return substr($output, 0, $size);
    }
}


// Small implementation of RC4, slightly based on http://www.php.net/manual/en/ref.mcrypt.php#87274
class RC4 {
    protected $i = 0;
    protected $j = 0;
    protected $S = array();
    protected $key;

    function __construct($key) {
        $this->key = $key;

        $this->S = range(0, 255);
        $j = 0;
        $n = strlen($key);
        for ($i=0; $i!=256; $i++) {
            $char = ord($key{$i % $n});
            $j = ($j + $this->S[$i] + $char) % 256;
            $this->swap($this->S[$i], $this->S[$j]);
        }
    }

    function encrypt($data) {
        return $this->_crypt($data);
    }

    function decrypt($data) {
        return $this->_crypt($data);
    }

    // Don't swap through XOR
    protected function swap(&$v1, &$v2) {
        $tmp = $v1;
        $v1 = $v2;
        $v2 = $tmp;
    }

    protected function _crypt($data) {
        $n = strlen($data);
        for ($m=0; $m<$n; $m++) {
            $this->i = ($this->i + 1) % 256;
            $this->j = ($this->j + $this->S[$this->i]) % 256;

            $this->swap($this->S[$this->i], $this->S[$this->j]);

            $char = ord($data[$m]);
            $char = $this->S[($this->S[$this->i] + $this->S[$this->j]) % 256] ^ $char;
            $data[$m] = chr($char);
        }
        return $data;
    }

}
