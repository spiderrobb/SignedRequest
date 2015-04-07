<?php
//require_once __dir__.'/../vendor/autoload.php';
namespace SpiderRobb\Test;

use PHPUnit_Framework_TestCase;
use SpiderRobb\SignedRequest;
use \Exception;

class SignedRequestTest extends PHPUnit_Framework_TestCase
{
	private $_data;

	/**
	 * this function sets up the test suite
	 *
	 * @return void
	 */
	public function setUp() {
		$this->_data = 'Test Data';
	}

	/**
	 * this function tests if an algorithm works
	 *
	 * @dataProvider algorithmProvider
	 *
	 * @param string $algo algorithm to test
	 *
	 * @return void
	 */
	public function testAlgorithm($algo)
	{
		// testing encode
		$encoded_data = SignedRequest::encode(
			$this->_data, array(
				'algorithm' => $algo
			)
		);

		// testing decode
		$decoded_data = SignedRequest::decode($encoded_data);

		// testing results
		$this->assertEquals($this->_data, $decoded_data);
	}

	/**
	 * this function returns the available algorithms
	 * dataprovider
	 *
	 * @return array
	 */
	public function algorithmProvider()
	{
		$algos = SignedRequest::getAlgorithms();
		foreach ($algos as &$algo) {
			$algo = array($algo);
		}
		return $algos;
	}

	/**
	 * this function tests the use of a bad algorithm on encode
	 *
	 * @expectedException     DomainException
	 * @expectedExceptionCode 103
	 *
	 * @return void
	 */
	public function testAlgorithmEncodeException()
	{
		SignedRequest::encode(
			$this->_data, array(
				'algorithm' => 'bad algorithm'
			)
		);
	}

	/**
	 * this function tests the use of bad timeout variable
	 *
	 * @dataProvider          invalidTimoutProvider
	 * @expectedException     InvalidArgumentException
	 * @expectedExceptionCode 100
	 *
	 * @param mixed $timeout timeout to try
	 *
	 * @return void
	 */
	public function testTimoutException($timeout)
	{
		SignedRequest::encode(
			$this->_data, array(
				'timeout' => $timeout
			)
		);
	}

	/**
	 * this function returns a list of invalid timeouts to test
	 * dataProvider
	 *
	 * @return array
	 */
	public function invalidTimoutProvider()
	{
		return array(
			array('string'),
			array(true),
			array(null),
			array(-500),
			array(0),
			array(array())
		);
	}

	/**
	 * this function tests the use of bad expires variable
	 *
	 * @dataProvider          invalidExpiresProvider
	 * @expectedException     InvalidArgumentException
	 * @expectedExceptionCode 101
	 *
	 * @param mixed $expires expire dates to try
	 *
	 * @return void
	 */
	public function testExpiresException($expires)
	{
		SignedRequest::encode(
			$this->_data, array(
				'expires' => $expires
			)
		);
	}

	/**
	 * this function returns a list of invalid expiration dates to test
	 * dataProvider
	 *
	 * @return array
	 */
	public function invalidExpiresProvider()
	{
		$list   = $this->invalidTimoutProvider();
		$list[] = array(time()-1);
		$list[] = array(time());
		return $list;
	}

	/**
	 * this function tests if issued_time option is or isn't setting the issued_time key
	 * like it should be
	 *
	 * @dataProvider issuedTimeProvider 
	 *
	 * @param mixed $time time t
	 *
	 * @return void
	 */
	public function testIssuedTimeOption($time, $expected)
	{
		// building signed request with issued time
		$encoded_data = SignedRequest::encode(
			$this->_data, array(
				'issued_at' => $time
			)
		);
		$encoded_time = time();

		// decoding raw data so we can see the issued time
		$decoded_raw_data = SignedRequest::decode(
			$encoded_data, array(
				'raw' => true
			)
		);

		// testing results
		if ($time !== false) {
			$this->assertArrayHasKey('issued_at', $decoded_raw_data);
		}
		if (isset($decoded_raw_data['issued_at'])) {
			if ($time === true) {
				// case where issued_at is created within the function
				$this->assertLessThanOrEqual($encoded_time, $decoded_raw_data['issued_at']);
				$this->assertGreaterThanOrEqual($expected, $decoded_raw_data['issued_at']);
			} else {
				// case where issued_at is created outside the function
				$this->assertEquals($expected, $decoded_raw_data['issued_at']);
			}
		}
	}

	/**
	 * this function retuns the params for testing issued_at key
	 * dataProvider
	 * 
	 * @return array
	 */
	public function issuedTimeProvider()
	{
		return array(
			array(date("Y-m-d H:i:s"), date("Y-m-d H:i:s")),
			array(time(), time()),
			array('random value', 'random value'),
			array(true, time()),
			array(false, null)
		);
	}

	/**
	 * this function tests if the timeout feature is working correctly
	 *
	 * @return void
	 */
	public function testTimoutNoExpire()
	{
		// building signed request
		$encoded_data = SignedRequest::encode(
			$this->_data, array(
				'timeout' => 5 // signed request espires in 5 seconds
			)
		);

		// decoding data right away
		$decoded_data = SignedRequest::decode($encoded_data);
		$this->assertEquals($this->_data, $decoded_data);
	}

	/**
	 * this function tests if the timeout feature is working correctly
	 *
	 * @expectedException     RuntimeException
	 * @expectedExceptionCode 207
	 *
	 * @return void
	 */
	public function testTimoutExpire()
	{
		// building signed request
		$encoded_data = SignedRequest::encode(
			$this->_data, array(
				'timeout' => 1 // signed request espires in 5 seconds
			)
		);
		sleep(2);

		// decoding data right away
		SignedRequest::decode($encoded_data);
	}

	/**
	 * this function tests the getAlgorithms function
	 *
	 * @return void
	 */
	public function testGetAlgorithms()
	{
		// getting algorithms
		$algos = SignedRequest::getAlgorithms();
		$this->assertNotEmpty($algos);
	}

	/**
	 * this function tests the setDefaultSecret function
	 * 
	 * @return void
	 */
	public function testSetDefaultSecret()
	{
		// set default secret
		$secret = 'My Super Secret Secret!! No Telling!';
		SignedRequest::setDefaultSecret($secret);

		// creating signed request
		$encoded_data1 = SignedRequest::encode($this->_data);
		$encoded_data2 = SignedRequest::encode(
			$this->_data, array(
				'secret' => $secret
			)
		);

		// check if both methods created the same secret
		$this->assertEquals($encoded_data1, $encoded_data2);

		// decoding both with opposit secret setting
		$decoded_data1 = SignedRequest::decode(
			$encoded_data1, array(
				'secret' => $secret
			)
		);
		$decoded_data2 = SignedRequest::decode($encoded_data2);

		// check again if both methods create same data
		$this->assertEquals($decoded_data1, $decoded_data2);
	}

	/**
	 * this function tests for the exception thrown when a signed requst has a bad signature
	 *
	 * @expectedException     RuntimeException
	 * @expectedExceptionCode 203
	 *
	 * @return void
	 */
	public function testBadSignature()
	{
		// building signed request
		$encoded_data = SignedRequest::encode($this->_data);
		$encoded_data = 'badsig'.$encoded_data;

		// decoding data
		SignedRequest::decode($encoded_data);
	}

	/*
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
			$expected_message = 'Signature does not match the data.';
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
	*/
}
?>