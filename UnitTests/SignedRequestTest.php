<?php
require_once dirname(__FILE__).'/../SignedRequest.php';
class SignedRequestTest extends PHPUnit_Framework_TestCase {
	private $_data;
	function setUp() {
		$this->_data = 'Test Data';
	}
	function testInvalidSignedRequest() {
		// testing to make sure invalid signed requests are handled correctly
		$bad_sr = 'This is not a valid signed request';
		try {
			$data = SignedRequest::decode($bad_sr);
		} catch (Exception $e) {
			$expected_message = 'Invalid Signed Request format.';
			$actual_message   = $e->getMessage();
			$this->assertEquals($expected_message, $actual_message);
		}
	}
	function testNoOptionalArguments() {
		// testing for correct signed request
		$expected_sr = 'LmL_f0Wi13Zlj21pt3-yrb3wz_fU0lDgoBOF4BwE7ZQ.eyJkYXRhIjoiVGVzdCBEYXRhIiwiYWxnb3JpdGhtIjoiSE1BQy1TSEEyNTYifQ';
		$actual_sr   = SignedRequest::encode($this->_data);
		$this->assertEquals($expected_sr, $actual_sr);
		// checking for correct decode
		$data        = SignedRequest::decode($actual_sr);
		$this->assertEquals($data, $this->_data);
	}
	function testMethodArgument() {
		// testing for correct signed request
		$expected_sr = 'uSYB5XP0OXoIF6IbbWFddetzZLh3dqx7yTYsXT-57ks.eyJkYXRhIjoiVGVzdCBEYXRhIiwiYWxnb3JpdGhtIjoiSE1BQy1TSEEyNTYiLCJtZXRob2QiOiJ0ZXN0TWV0aG9kQXJndW1lbnQifQ';
		$actual_sr   = SignedRequest::encode(
			$this->_data, array(
				'method' => 'testMethodArgument'
			)
		);
		$this->assertEquals($expected_sr, $actual_sr);
		// checking for correct decode
		$data        = SignedRequest::decode(
			$actual_sr, array(
				'method' => 'testMethodArgument'
			)
		);
		$this->assertEquals($data, $this->_data);
	}
	function testSecretArgument() {
		// testing for correct signed request
		$expected_sr = 'FjHGGo44hiz7RDYRFSOukAR_tlta7mC3RjvqNnna-6s.eyJkYXRhIjoiVGVzdCBEYXRhIiwiYWxnb3JpdGhtIjoiSE1BQy1TSEEyNTYifQ';
		$actual_sr   = SignedRequest::encode(
			$this->_data, array(
				'secret' => 'testSecretArgument'
			)
		);
		$this->assertEquals($expected_sr, $actual_sr);
		// checking for correct decode
		$data        = SignedRequest::decode(
			$actual_sr, array(
				'secret' => 'testSecretArgument'
			)
		);
		$this->assertEquals($data, $this->_data);
	}
	function testTimoutArgument() {
		// testing timeout
		$actual_sr = SignedRequest::encode(
			$this->_data, array(
				'timeout' => 1
			)
		);
		$data      = SignedRequest::decode($actual_sr);
		$this->assertEquals($data, $this->_data);
		// testing timeout feature
		sleep(2);
		try {
			$data = SignedRequest::decode($actual_sr);
		} catch (Exception $e) {
			$expected_message = 'This Signed Request has expired.';
			$actual_message   = $e->getMessage();
			$this->assertEquals($expected_message, $actual_message);
		}
	}
	function testInvalidSignature() {
		// sr with invalid signature
		$invalid_sr = 'Invalid.eyJkYXRhIjoiVGVzdCBEYXRhIiwiYWxnb3JpdGhtIjoiSE1BQy1TSEEyNTYifQ';
		try {
			$data = SignedRequest::decode($invalid_sr);
		} catch (Exception $e) {
			$expected_message = 'Signature does not match the data';
			$actual_message   = $e->getMessage();
			$this->assertEquals($expected_message, $actual_message);
		}
	}
	function testInvalidMethodArguments() {
		// creating sr with method
		$method_sr    = SignedRequest::encode(
			$this->_data, array(
				'method' => 'testInvalidMethodArguments'
			)
		);
		// testing exception for specifying method when needed
		try {
			$data = SignedRequest::decode($method_sr);
			$this->assertNotEquals($data, $this->_data);
		} catch (Exception $e) {
			$expected_message = 'This Signed Request requires a method.';
			$actual_message   = $e->getMessage();
			$this->assertEquals($expected_message, $actual_message);
		}
		// testing exception for method if method does not match
		try {
			$data = SignedRequest::decode(
				$method_sr, array(
					'method' => 'WrongMethod'
				)
			);
			$this->assertNotEquals($data, $this->_data);
		} catch (Exception $e) {
			$expected_message = 'This Signed Request does not match the given method.';
			$actual_message   = $e->getMessage();
			$this->assertEquals($expected_message, $actual_message);
		}
		// creating sr with no method
		$no_method_sr = SignedRequest::encode($this->_data);
		// testing exception for specifying method when no method is required
		try {
			$data = SignedRequest::decode(
				$no_method_sr, array(
					'method' => 'testInvalidMethodArguments'
				)
			);
			$this->assertNotEquals($data, $this->_data);
		} catch (Exception $e) {
			$expected_message = 'This Signed Request does not require a method.';
			$actual_message   = $e->getMessage();
			$this->assertEquals($expected_message, $actual_message);
		}
	}
	function testInvalidAlgorithm() {
		// testing to make sure exception is thrown for invalid algorithm
		$invalid_algorithm_sr = 'FJqLIdSlXRQyUpoBP1zVGJr3zrCRL5vyAx91Dejp0qs.eyJkYXRhIjoiVGVzdCBEYXRhIiwiYWxnb3JpdGhtIjoiSE1BQy1NRDUifQ';
		try {
			$data = SignedRequest::decode($invalid_algorithm_sr);
			$this->assertNotEquals($data, $this->_data);
		} catch (Exception $e) {
			$expected_message = 'Algorithm is not supported, HMAC-SHA256 expected.';
			$actual_message   = $e->getMessage();
			$this->assertEquals($expected_message, $actual_message);
		}
	}
	function testRawOptionArgument() {
		// creating SignedRequest with full options
		$full_sr = SignedRequest::encode(
			$this->_data, array(
				'method'  => 'TestRawOptionArgument',
				'secret'  => 'superDuperSecret',
				'timeout' => 2
			)
		);
		// decoding with raw flag
		$raw_data = SignedRequest::decode(
			$full_sr, array(
				'method' => 'TestRawOptionArgument',
				'secret' => 'superDuperSecret',
				'raw'    => true
			)
		);
		// checking keys
		$this->assertArrayHasKey('data', $raw_data);
		$this->assertArrayHasKey('algorithm', $raw_data);
		$this->assertArrayHasKey('method', $raw_data);
		$this->assertArrayHasKey('expires', $raw_data);
		// checking values
		$this->assertEquals($raw_data['data'], $this->_data);
		$this->assertEquals($raw_data['algorithm'], 'HMAC-SHA256');
		$this->assertEquals($raw_data['method'], 'TestRawOptionArgument');
	}
}
?>