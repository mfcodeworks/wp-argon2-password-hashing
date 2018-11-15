<?php
/**
 * Plugin Name:    WP Argon2 Password Hashing
 * Description:    Requires PHP 7.2. Implement PHP 7.2 new Argon2i password hashing algorithm. For existing users, password will be rehashed with Argon2i on next sucessful login.
 * Version:        1.0.0
 * Author:         MF Softworks
 * Author URI:     https://mf.nygmarosebeauty.com/
 * License:        GPLv3
 */

/**
 * Define plugin version
 */ 
define('WP_ARGON2_PASSWORD_HASHING', '1.0.0');

// Hash password with argon2i
if ( !function_exists('wp_hash_password') ) {
    function wp_hash_password($password) {
        // Set argon2i cost arguments
		$password = password_hash($password, PASSWORD_ARGON2I, ['memory_cost' => 4096, 'time_cost' => 4, 'threads' => 2]);
        return $password;
    }
}

// Verify hash against argon2i and md5/old style, update old hashes to new argon2i
if ( !function_exists('wp_check_password') ) {
    function wp_check_password($password, $hash, $user_id = '') {
        global $wp_hasher;

         // If the hash is still md5...
        if ( strlen($hash) <= 32 ) {
            $check = hash_equals( $hash, md5( $password ) );
            
            // Rehash using new hash.
            if ( $check && $user_id ) {
                wp_set_password($password, $user_id);
                $hash = wp_hash_password($password);
            }
        }

        // If hash using old WordPress style hashing...
        if ( empty($wp_hasher) ) {
            require_once( ABSPATH . WPINC . '/class-phpass.php');

            // By default, use the portable hash from phpass
            $wp_hasher = new PasswordHash(8, true);

            $check = $wp_hasher->CheckPassword($password, $hash);

            // Rehash using new hash.
            if ( $check && $user_id ) {
                wp_set_password($password, $user_id);
                $hash = wp_hash_password($password);
            }
        }

        // If check still hasn't succeeded check with Argon2i as per usual
        if(!$check) {
            $check = password_verify($password, $hash);
        }

        return apply_filters('check_password', $check, $password, $hash, $user_id);
    }
}

?>