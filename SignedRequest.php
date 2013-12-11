<?php
class SignedRequest
{
	private static $_default_secret = 'sxtytuyuhiyf46576798y8g6ftuvy';
	public static function encode($data, array $args = array())
	{
		// init variables
		$algorithm = 'HMAC-SHA256';
		$arg_method    = false;
		$arg_timeout   = false;
		$arg_secret    = self::$_default_secret;
		extract($args, EXTR_PREFIX_ALL, 'arg');
		
		// building data array for signed request
		$data_wrapper = array(
			'data'      => $data,
			'algorithm' => $algorithm
		);
		
		// checking for method
		if ($arg_method !== false) {
			$data_wrapper['method'] = $arg_method;
		}
		
		// checking for timeout
		if ($arg_timeout !== false) {
			$data_wrapper['expires'] = time() + $arg_timeout; 
		}
		
		// building encoded data
		$json_encoded_data = json_encode($data_wrapper);
		
		// json encoded data
		$hash = hash_hmac('sha256', $json_encoded_data, $arg_secret, true);
		
		// building signature
		$signature = self::_base64URLEncode($hash);
		
		// building encoded
		$payload = self::_base64URLEncode($json_encoded_data);
		
		// returning signed request
		return $signature.'.'.$payload;
	}
	
	public static function decode($signedrequest, array $args = array())
	{
		// arguments
		$algorithm = 'HMAC-SHA256';
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
		if (!isset($wrapped_data['algorithm']) || $wrapped_data['algorithm'] !== $algorithm) {
			throw new Exception('Algorithm is not supported, HMAC-SHA256 expected.');
		}
		
		// checking the signature
		$expected_signature = hash_hmac('sha256', $json_encoded_data, $arg_secret, true);
		if ($signature !== $expected_signature) {
			throw new Exception('Signature does not match the data');
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
	private static function _base64URLEncode($data) 
	{ 
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); 
	}
	private static function _base64URLDecode($data) { 
		return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
	}
}
?>