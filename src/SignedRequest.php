<?php
/**
 * This file contains the SignedRequest Class that can be
 * used for endcoding and decoding signed requests
 *
 * PHP 5
 *
 * @author Robbin Harris <spiderrobb+git@gmail.com>
 */
namespace SpiderRobb;

use Exception;

/**
 * The SignedRequest class can be used to encode and decode
 * signed reqeusts.
 *
 * Usage: $sr = SignedRequest::encode($data, $args);
 *        OR
 *        $data = SignedRequest::decode($sr, $args);
 *
 * @author Robbin Harris <spiderrobb+git@gmail.com>
 */
class SignedRequest
{
	/**
	 * this variable is used as the default secret if you do not set yourown
	 */
	private static $_default_secret = 'sxtytuyuhiyf46576798y8g6ftuvy';

	/**
	 * this function allows you to specify your own default secret
	 *
	 * @param string $default default secret to use
	 *
	 * @return void
	 */
	public static function setDefaultSecret($default)
	{
		self::$_default_secret = $default;
	}

	/**
	 * this function can encode any data into a signedrequest
	 *
	 * @param mixed $data data you wish to wrap in a signed request
	 * @param array $args array of optional arguments for your signed request
	 *                    [secret]      the secret used to build signature of signed request
	 *                                  if not specified class default will be used
	 *                    [method]      a signed request given a method can 
	 *                                  only be decoded with the same method specified
	 *                    [timeout]     number of seconds before signed requests expires
	 *                    [expires]     unix timestamp of expiration date *overrides timout
	 *                    [issued_time] boolean if true adds issued_at key with date signed
	 *                                  request was created
	 *                    [algorithm]   The algorithm used to generate the signature
	 *                                  HMAC-SHA256 (standard) used by default
	 *
	 * @return string in the format signature.payload
	 */
	public static function encode($data, array $args = array())
	{
		// init variables
		$arg_algorithm     = 'HMAC-SHA256';
		$arg_method        = false;
		$arg_timeout       = false;
		$arg_expires       = false;
		$arg_issued_time   = false;
		$arg_secret        = self::$_default_secret;
		extract($args, EXTR_PREFIX_ALL, 'arg');
		
		// checking if algorithm is supported
		if (!in_array($arg_algorithm, self::getAlgorithms())) {
			throw new Exception('Algorithm is not supported.', 10);
		}
		
		// getting hash algorithm
		$parts     = explode('-', $arg_algorithm);
		$algorithm = strtolower($parts[1]);
		
		// building data array for signed request
		$data_wrapper = array(
			'data'      => $data,
			'algorithm' => $arg_algorithm
		);
		
		// checking if they want created time
		if ($arg_issued_time === true) {
			$data_wrapper['issued_at'] = time();
		}
		
		// checking for method
		if ($arg_method !== false) {
			$data_wrapper['method'] = $arg_method;
		}
		
		// checking for timeout
		if ($arg_timeout !== false) {
			if (!is_numeric($arg_timeout)) {
				throw new Exception('Invalid timeout, must be numeric', 11);
			}
			$data_wrapper['expires'] = time() + $arg_timeout; 
		}
		
		// checking for specific expiration date
		if ($arg_expires !== false) {
			if (!is_numeric($arg_expires)) {
				throw new Exception('Invalid expire time, must be numeric', 12);
			}
			if (!isset($data_wrapper['expires']) || $arg_expires < $data_wrapper['expires']) {
				$data_wrapper['expires'] = $arg_expires;
			}
		}
		
		// building encoded data
		$json_encoded_data = json_encode($data_wrapper);
		
		// building encoded
		$payload = self::_base64URLEncode($json_encoded_data);
		
		// json encoded data
		$hash = hash_hmac($algorithm, $payload, $arg_secret, true);
		
		// building signature
		$signature = self::_base64URLEncode($hash);
		
		// returning signed request
		return $signature.'.'.$payload;
	}
	
	/**
	 * the decode function takes a signed request and decodes it
	 *
	 * @param string $signedrequest signed request in form signature.payload
	 * @param array  $args          array of args or optional options
	 *                              [raw]    if true the entire signed request payload is returned
	 *                                       this is useful when decoding signed requests not generated
	 *                                       with this class
	 *                              [method] method passed to encode function
	 *                              [secret] sam secret used to encode the data
	 *                                       if not specified class default will be used
	 * 
	 * @return mixed
	 */
	public static function decode($signedrequest, array $args = array())
	{
		// arguments
		$arg_raw       = false;
		$arg_method    = false;
		$arg_secret    = self::$_default_secret;
		extract($args, EXTR_PREFIX_ALL, 'arg');
		
		// separating the signature from the payload
		$parts = explode('.', $signedrequest);
		
		// checking if we have the correct number of parts
		if (count($parts) !== 2) {
			throw new Exception('Invalid Signed Request format.');
		}
		
		// getting signature and payload
		$signature         = self::_base64URLDecode($parts[0]);
		$json_encoded_data = self::_base64URLDecode($parts[1]);
		
		// getting raw wrapped data
		$wrapped_data = json_decode($json_encoded_data, true);
		
		// checking algorithm
		if (!isset($wrapped_data['algorithm']) || !in_array($wrapped_data['algorithm'], self::getAlgorithms())) {
			throw new Exception('Algorithm is not supported.');
		}
		
		// getting hash algorithm
		$alg_parts     = explode('-', $wrapped_data['algorithm']);
		$algorithm = strtolower($alg_parts[1]);
		
		// checking the signature
		$expected_signature = hash_hmac($algorithm, $parts[1], $arg_secret, true);
		if ($signature !== $expected_signature) {
			throw new Exception('Signature does not match the data.');
		}
		
		// checking method
		if (isset($wrapped_data['method']) && $arg_method === false) {
			throw new Exception('This Signed Request requires a method.');
		}
		if (!isset($wrapped_data['method']) && $arg_method !== false) {
			throw new Exception('This Signed Request does not require a method.');
		}
		if (isset($wrapped_data['method']) && $arg_method !== $wrapped_data['method']) {
			throw new Exception('This Signed Request does not match the given method.');
		}
		
		// checking expiration of signed request
		if (isset($wrapped_data['expires']) && $wrapped_data['expires'] < time()) {
			throw new Exception('This Signed Request has expired.');
		}
		
		// returning the data
		if ($arg_raw) {
			return $wrapped_data;
		}
		return $wrapped_data['data'];
	}

	/**
	 * this function base64 (url safe) encodes a string
	 *
	 * @param string $data data to encode
	 *
	 * @return string encoded data
	 */
	private static function _base64URLEncode($data) 
	{ 
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); 
	}

	/**
	 * this function base64 (url safe) decodes a string
	 *
	 * @param string $data to decode
	 *
	 * @return string decoded data
	 */
	private static function _base64URLDecode($data) { 
		return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
	}

	/**
	 * this function returns the list of supported algorithms
	 * 
	 * @return array
	 */
	public static function getAlgorithms()
	{
		// creating full list of supported algorithms
		$algos = hash_algos();
		foreach ($algos as &$algo) {
			$algo = 'HMAC-'.strtoupper($algo);
		}
		return $algos;
	}
}
?>