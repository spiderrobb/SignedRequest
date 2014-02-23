<?php
class SignedRequest
{
	private static $_default_secret = 'sxtytuyuhiyf46576798y8g6ftuvy';
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
		
		// json encoded data
		$hash = hash_hmac($algorithm, $json_encoded_data, $arg_secret, true);
		
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
		$parts     = explode('-', $wrapped_data['algorithm']);
		$algorithm = strtolower($parts[1]);
		
		// checking the signature
		$expected_signature = hash_hmac($algorithm, $json_encoded_data, $arg_secret, true);
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
	private static function _base64URLEncode($data) 
	{ 
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); 
	}
	private static function _base64URLDecode($data) { 
		return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
	}
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