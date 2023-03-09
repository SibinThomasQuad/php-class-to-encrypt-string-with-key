<?php
class Keys
{
    public static function secret_key()
    {
        $secret_key = "YOUR SECRET KEY";
        return $secret_key;
    }
    public static function secret_iv()
    {
        $secret_iv = "YOUR SECRET IV";
        return $secret_iv;
    }
}
class Cypher
{
    public static function encrypt($string)
    {
        //This is the function to encrypt the string with the key
        
        $encrypt_method = "AES-256-CBC";
        $secret_key = Keys::secret_key();
        $secret_iv = Keys::secret_iv();
        $key = hash('sha256', $secret_key);
        $iv = substr(hash('sha256', $secret_iv), 0, 16);
        $ssl_encrypt = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
        $encrypted_string = base64_encode($ssl_encrypt);
        return $encrypted_string;
    }
    
    public static function decrypt($cypher)
    {
        //This is the function to decrypt the string with the key
        
        $encrypt_method = "AES-256-CBC";
        $secret_key = Keys::secret_key();
        $secret_iv = Keys::secret_iv();
        $key = hash('sha256', $secret_key);
        $iv = substr(hash('sha256', $secret_iv), 0, 16);
        $decrypted_string = openssl_decrypt(base64_decode($cypher), $encrypt_method, $key, 0, $iv);
        return $decrypted_string;
    }
}
?>
