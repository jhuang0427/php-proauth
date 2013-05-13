<?php

require_once '../../lib/oauth/OAuthUtil.php';
require_once 'PHPUnit/Framework.php';

class OAuthUtilsTest extends PHPUnit_Framework_TestCase
{
	public function testGetIfSet()
	{
		$arr = array();
		$no_arr = 'hi!';

		$this->assertEquals(OAuthUtil::getIfSet($arr, 'x', 'default'), 'default');
		$this->assertEquals(OAuthUtil::getIfSet($arr, 'x'), NULL);
		$this->assertEquals(OAuthUtil::getIfSet($no_var, 'x', 'default'), 'default');
		$this->assertEquals(OAuthUtil::getIfSet($no_arr, 'x', 'default'), 'default');

		$arr['x'] = '';
		$this->assertEquals(OAuthUtil::getIfSet($arr, 'x', 'default'), 'default');

		$arr['x'] = 'w00t';
		$this->assertEquals(OAuthUtil::getIfSet($arr, 'x', 'default'), 'w00t');
	}

	/**
	 * test taken from http://oauth.googlecode.com/svn/code/php/tests/OAuthUtilTest.php mostly.
	 **/
	public function testUrlencode()
	{
		// Tests taken from
		// http://wiki.oauth.net/TestCases ("Parameter Encoding")
		$this->assertEquals('abcABC123', OAuthUtil::urlEncode('abcABC123'));
		$this->assertEquals('-._~',      OAuthUtil::urlEncode('-._~'));
		$this->assertEquals('%25',       OAuthUtil::urlEncode('%'));
		$this->assertEquals('%2B',       OAuthUtil::urlEncode('+'));
		$this->assertEquals('%0A',       OAuthUtil::urlEncode("\n"));
		$this->assertEquals('%20',       OAuthUtil::urlEncode(' '));
		$this->assertEquals('%7F',       OAuthUtil::urlEncode("\x7F"));
		$this->assertEquals('%C2%80',    OAuthUtil::urlEncode(mb_convert_encoding(pack('n', 0x0080), 'UTF-8', 'UTF-16')));
		$this->assertEquals('%E3%80%81', OAuthUtil::urlEncode(mb_convert_encoding(pack('n', 0x3001), 'UTF-8', 'UTF-16')));
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testUrlencode2()
	{
		OAuthUtil::urlEncode(NULL);
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testUrlencode3()
	{
		OAuthUtil::urlEncode(new stdClass());
	}

	public function testUrldecode()
	{
		// Tests taken from
		// http://wiki.oauth.net/TestCases ("Parameter Encoding")
		$this->assertEquals('abcABC123', OAuthUtil::urlDecode('abcABC123'));
		$this->assertEquals('-._~',      OAuthUtil::urlDecode('-._~'));
		$this->assertEquals('%',         OAuthUtil::urlDecode('%25'));
		$this->assertEquals('+',         OAuthUtil::urlDecode('%2B'));
		$this->assertEquals("\n",        OAuthUtil::urlDecode('%0A'));
		$this->assertEquals(' ',         OAuthUtil::urlDecode('%20'));
		$this->assertEquals("\x7F",      OAuthUtil::urlDecode('%7F'));
		$this->assertEquals(mb_convert_encoding(pack('n', 0x0080), 'UTF-8', 'UTF-16'),  OAuthUtil::urlDecode('%C2%80'));
		$this->assertEquals(mb_convert_encoding(pack('n', 0x3001), 'UTF-8', 'UTF-16'),  OAuthUtil::urlDecode('%E3%80%81'));

		// Additional test as per section 3.4.1.3.1
		$this->assertEquals('2 q',         OAuthUtil::urlDecode('2+q'));
	}

	public function testIsKnownOAuthParameter()
	{
		$this->assertEquals(true, OAuthUtil::isKnownOAuthParameter('oauth_consumer_key'));
		$this->assertEquals(false, OAuthUtil::isKnownOAuthParameter('oAuth_consumer_key'));
		$this->assertEquals(false, OAuthUtil::isKnownOAuthParameter(' oauth_consumer_key'));
		$this->assertEquals(false, OAuthUtil::isKnownOAuthParameter(NULL));
	}

	public function testParseHttpAuthorizationHeader()
	{
		$this->assertEquals(false, OAuthUtil::parseHttpAuthorizationHeader('Digest realm="abc", x="y"'));
		$this->assertEquals(false, OAuthUtil::parseHttpAuthorizationHeader('OAuth'));
		$this->assertEquals(array('realm' => 'site'), OAuthUtil::parseHttpAuthorizationHeader('OAuth realm="site"'));
		$this->assertEquals(array('realm' => ''), OAuthUtil::parseHttpAuthorizationHeader('OAuth realm=""'));

		$this->assertEquals(array('realm' => 'http://sp.example.com/',
				'oauth_consumer_key' => '0685bd9184jfhq22',
				'oauth_token' => 'ad180jjd733klru7',
				'oauth_signature_method' => 'HMAC-SHA1',
				'oauth_signature' => 'wOJIO9A2W5mFwDgiDvZbTSMK/PY=',
				'oauth_timestamp' => '137131200',
				'oauth_nonce' => '4572616e48616d6d65724c61686176',
				'oauth_version' => '1.0'),
			OAuthUtil::parseHttpAuthorizationHeader('OAuth realm="http://sp.example.com/",
                oauth_consumer_key="0685bd9184jfhq22",
                oauth_token="ad180jjd733klru7",
                oauth_signature_method="HMAC-SHA1",
                oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
                oauth_timestamp="137131200",
                oauth_nonce="4572616e48616d6d65724c61686176",
                oauth_version="1.0"
		'));
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testParseHttpAuthorizationHeader2()
	{
		OAuthUtil::parseHttpAuthorizationHeader('OAuth realm="http://sp.exa');
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testParseHttpAuthorizationHeader3()
	{
		OAuthUtil::parseHttpAuthorizationHeader('OAuth realm="site", oauth_token="test\"lol"');
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testParseHttpAuthorizationHeader4()
	{
		OAuthUtil::parseHttpAuthorizationHeader('OAuth realm="site",,,,,,,,, oauth_token="xxx"');
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testParseHttpAuthorizationHeader5()
	{
		OAuthUtil::parseHttpAuthorizationHeader('OAuth realm="site" oauth_token="xxx"');
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testParseHttpAuthorizationHeader6()
	{
		OAuthUtil::parseHttpAuthorizationHeader('OAuth realm="site", oauth_token=xxx');
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testParseHttpAuthorizationHeader7()
	{
		OAuthUtil::parseHttpAuthorizationHeader('OAuth realm="site, oauth_token=xxx"');
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testParseHttpAuthorizationHeader8()
	{
		OAuthUtil::parseHttpAuthorizationHeader('OAuth realm="site", oauth_token="xxx');
	}

	public function testNormalizeRequestURL()
	{
		$this->assertEquals('http://example.com/resource', OAuthUtil::normalizeRequestURL('HTTP://Example.com:80/resource?id=123'));
		$this->assertEquals('https://example.net/resource/id/123', OAuthUtil::normalizeRequestURL('HTTPs://Example.NET/resource/id/123#xyz'));
		$this->assertEquals('https://example.com/', OAuthUtil::normalizeRequestURL('https://example.com'));
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testNormalizeRequestURL2()
	{
		OAuthUtil::normalizeRequestURL('dsgdhkj');
	}

	public function testValidateCallbackURL()
	{
		$this->assertEquals('oob', OAuthUtil::validateCallbackURL('oob'));
		$this->assertEquals('https://example.net/id/123', OAuthUtil::validateCallbackURL('https://example.net/id/123'));
		$this->assertEquals('https://example.net/id/123?x=y&z=das%20das', OAuthUtil::validateCallbackURL('https://example.net/id/123?x=y&z=das%20das'));
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testValidateCallbackURL2()
	{
		OAuthUtil::validateCallbackURL('chrome://local/stuff');
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testValidateCallbackURL3()
	{
		OAuthUtil::validateCallbackURL("whadd\r\nup");
	}

	public function testSplitHttpResponse()
	{
		$some_headers = "HTTP/1.0 404 Not Found\r\n" .
			"Date: Sun, 22 Nov 2009 15:43:44 GMT\r\n" .
			"Server: Apache/2.2.4 (Linux/SUSE) mod_ssl/2.2.4\r\n" .
				"\tOpenSSL/0.9.8e PHP/5.2.6 with Suhosin-Patch mod_python/3.3.1 Python/2.5.1 mod_perl/2.0.3 Perl/v5.8.8\r\n" .
			"Connection: Keep-Alive\r\n" .
			"Keep-Alive: timeout=15, max=100\r\n" .
			"Etag: \"1cad180-67187-31a3e140\"\r\n";

		$headers_expected = array('date' => 'Sun, 22 Nov 2009 15:43:44 GMT',
			'server' => 'Apache/2.2.4 (Linux/SUSE) mod_ssl/2.2.4 OpenSSL/0.9.8e PHP/5.2.6 with Suhosin-Patch mod_python/3.3.1 Python/2.5.1 mod_perl/2.0.3 Perl/v5.8.8',
			'connection' => 'Keep-Alive',
			'keep-alive' => 'timeout=15, max=100',
			'etag' => '"1cad180-67187-31a3e140"');

		$headers_actual = array();
		OAuthUtil::splitHttpResponse($some_headers . "\r\nHello World!", $headers_actual, $body_actual);
		$this->assertEquals($headers_expected, $headers_actual);
		$this->assertEquals('Hello World!', $body_actual);

		$some_headers .= "WWW-Authenticate: OAuth realm=\"http://sp.example.com\",\r\n" .
			"\toauth_problem=\"version_rejected\",\r\n" .
			"\toauth_acceptable_versions=\"1.0-1.0\"\r\n" .
			"\toauth_problem_advice=\"Fix%20your%20client\"\r\n";

		$headers_expected['www-authenticate'] = 'OAuth realm="http://sp.example.com", oauth_problem="version_rejected", oauth_acceptable_versions="1.0-1.0" ' .
			'oauth_problem_advice="Fix%20your%20client"';

		$headers_actual = array();
		OAuthUtil::splitHttpResponse($some_headers, $headers_actual, $body_actual);
		$this->assertEquals($headers_expected, $headers_actual);
		$this->assertEquals('', $body_actual);

		$headers_actual = array();
		OAuthUtil::splitHttpResponse("HTTP/1.1 200 OK\r\n\r\n", $headers_actual, $body_actual);
		$this->assertEquals(array(), $headers_actual);
		$this->assertEquals('', $body_actual);
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testSplitHttpResponse2()
	{
		$headers_actual = array();
		OAuthUtil::splitHttpResponse("HTTP/1.1 200 OK\r\n\tContent-Type: text/html\r\n\r\n", $headers_actual, $body_actual);
	}

	/**
	 * @expectedException OAuthException
	 **/
	public function testSplitHttpResponse3()
	{
		$headers_actual = array();
		OAuthUtil::splitHttpResponse("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nlol wat\r\n\r\n", $headers_actual, $body_actual);
	}

	public function testSplitParametersMap()
	{
		// tests inspired by http://wiki.oauth.net/TestCases
		$this->assertEquals(array(), OAuthUtil::splitParametersMap(''));
		$this->assertEquals(array('name' => ''), OAuthUtil::splitParametersMap('name'));
		$this->assertEquals(array('name' => ''), OAuthUtil::splitParametersMap('name='));
		$this->assertEquals(array('name' => ''), OAuthUtil::splitParametersMap('name=&'));
		$this->assertEquals(array('a' => 'b'), OAuthUtil::splitParametersMap('a=b'));
		$this->assertEquals(array('a' => 'b', 'c' => 'd'), OAuthUtil::splitParametersMap('a=b&c=d'));
		$this->assertEquals(array('a' => 'x y', 'a2' => 'x!y'), OAuthUtil::splitParametersMap('a=x%20y&a2=x%21y'));
		$this->assertEquals(array('x!y' => 'a', 'x' => 'a'), OAuthUtil::splitParametersMap('x=a&x%21y=a'));
	}
}
