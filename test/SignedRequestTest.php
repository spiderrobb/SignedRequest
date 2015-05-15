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

	/**
	 * this function returns the params for testing method
	 * provider
	 *
	 * @return array
	 */
	public function methodTestProvider()
	{
		return array(
			array(
				'TESTMETHOD',
				'TESTMETHOD',
				false,
				false // should work fine
			),
			array(
				'TESTMETHOD',
				'BADMETHOD',
				'RuntimeException',
				206 // methods do not match
			),
			array(
				'TESTMETHOD',
				false, // no method
				'RuntimeException',
				204 // this request expected a method
			),
			array(
				false,
				'BADMETHOD',
				'RuntimeException',
				205 // this request does not require a method
			)
		);
	}

	/**
	 * this function tests the method feature of the signed request class
	 *
	 * @dataProvider methodTestProvider
	 *
	 * @param string $encode_method method to encode with
	 * @param string $decode_method method to decode with
	 * @param string $exception     expected exception to be thrown
	 * @param int    $code          expected exception code
	 *
	 * @return void
	 */
	public function testGoodMethodOption($encode_method, $decode_method, $exception, $code)
	{
		// encoding data
		$encoded_data = SignedRequest::encode(
			$this->_data, array(
				'method' => $encode_method
			)
		);

		// checking if exception is expected
		if ($exception !== false) {
			$this->setExpectedException($exception, '', $code);
		}

		// decoding data
		$decoded_data = SignedRequest::decode(
			$encoded_data, array(
				'method' => $decode_method
			)
		);

		// test if data matches
		$this->assertEquals($this->_data, $decoded_data);
	}
}
?>