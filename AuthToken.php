<?php

/*
 * This file is part of the LoginBox Package.
 *
 * (c) Loginbox <developers@loginbox.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Loginbox\Awt;

use InvalidArgumentException;

/**
 * Class AuthToken. Create and verify authentication tokens.
 *
 * @package Loginbox\Awt
 */
class AuthToken
{
    /**
     * Generate an authentication token.
     *
     * @param array  $payload The payload in the form of array.
     * @param string $key     The key to sign the token.
     *
     * @return string
     * @throws InvalidArgumentException
     */
    public static function generate(array $payload, $key)
    {
        // Check if payload is array
        if (!is_array($payload)) {
            throw new InvalidArgumentException('Token payload must be an array');
        }

        // Check if payload or key is empty
        if (empty($payload) || empty($key)) {
            throw new InvalidArgumentException('Both payload and key must have a value');
        }

        // Encode with json and base64
        $payloadEncoded = base64_encode(json_encode($payload, JSON_FORCE_OBJECT));

        // Create signature
        $signature = hash_hmac($algo = 'SHA256', $data = $payloadEncoded, $key);

        // Return combined key
        return implode('.', [$payloadEncoded, $signature]);
    }

    /**
     * Get the payload from the token.
     *
     * @param string  $token      The authentication token.
     * @param boolean $jsonDecode Whether to decode the payload from json to array.
     *
     * @return mixed Array or json string according to $jsonDecode value.
     */
    public static function getPayload($token, $jsonDecode = true)
    {
        // Split parts
        list($payload, $signature) = explode('.', $token);

        // Decode first part
        $payloadJSON = base64_decode($payload);

        // Choose to decode or not
        if ($jsonDecode) {
            return json_decode($payloadJSON, true);
        }

        // Return json
        return $payloadJSON;
    }

    /**
     * Verify the given token with the given signature key.
     *
     * @param string $token The authentication token.
     * @param string $key   The signature secret key.
     *
     * @return boolean True if valid, false otherwise.
     */
    public static function verify($token, $key)
    {
        // Check values
        if (empty($token) || empty($key)) {
            return false;
        }

        // Split parts
        list($payloadJSON_encoded, $signature) = explode('.', $token);

        // Generate signature to verify
        $signatureGenerated = hash_hmac('SHA256', $payloadJSON_encoded, $key);

        return ($signature === $signatureGenerated);
    }
}
