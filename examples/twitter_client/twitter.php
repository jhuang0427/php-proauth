<?php
/*
 * This example code is hereby released into Public Domain.
 */

use proauth;

$_config = array(
	/* get your own consumer key + secret at http://twitter.com/oauth */
	'key' => '',
	'secret' => ''
);

/* include client library */
require_once dirname(__FILE__) . '/../../lib/oauth/OAuthClient.php';

/* derive our client class from OAuthCurlClient.
	to use OAuthCurlClient, your PHP setup needs to be configured with the curl extension. */

class MyTwitterClient extends OAuthCurlClient
{
	const URL_TEMP_TOKEN = 'http://twitter.com/oauth/request_token';
	const URL_AUTHORIZE = 'http://twitter.com/oauth/authorize';
	const URL_AUTHENTICATE = 'http://twitter.com/oauth/authenticate';
	const URL_ACCESS_TOKEN = 'http://twitter.com/oauth/access_token';

	public function __construct($consumer_key, $consumer_secret, OAuthToken $token = NULL)
	{
		parent::__construct(
				new OAuthConsumer($consumer_key, $consumer_secret),
				new OAuthSignatureHMACSHA1(),
				$token
			);
	}

	public function getTempToken($callback_url)
	{
		// assume_www_encoded = true because of this bug:
		// http://code.google.com/p/twitter-api/issues/detail?id=1263
		return $this->_getTempToken(self::URL_TEMP_TOKEN, array('oauth_callback' => $callback_url), true);
	}

	public function redirectToAuth(OAuthToken $tmp_token, $immediate = false)
	{
		$url = ($immediate ? self::URL_AUTHENTICATE : self::URL_AUTHORIZE);
		$url .= '?' . http_build_query(
				array('oauth_token' => $tmp_token->getToken()), '', '&');

		header('HTTP/1.0 302 Found');
		header('Location: ' . $url);
	}

	public function getAccessToken($verifier)
	{
		return $this->_getAccessToken(self::URL_ACCESS_TOKEN, array('oauth_verifier' => $verifier), NULL, true);
	}
}


/* the client has been defined with ease, now let's do stuff! */

/* we use _SESSION to store the temp_key, you'd normally rather use a temp table in your database for that */

session_start();

if(isset($_GET['logout']))
{
	session_destroy();
	session_start();
}

$has_temp_token = !empty($_SESSION['temp_token']);
$has_access_token = !empty($_SESSION['authd_token']);

if(count($_GET) == 0 && !$has_access_token)
{
	echo 'Click <a href="?do_it=1">here</a> to login with twitter.';
}
elseif(isset($_GET['do_it']) && !$has_access_token)
{
	/* login: first step */

	try
	{
		$clnt = new MyTwitterClient($_config['key'], $_config['secret']);

		/* make sure $_SERVER['HTTP_HOST'] is safe to use like that, e.g. by properly configuring your web server */
		$tmp_token = $clnt->getTempToken('http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME']);

		/* note: it's dangerous to use serialize/deserialize on data that could have been
			tampered with by 3rd parties, so do NOT store it in a cookie like this! */
		$_SESSION['temp_token'] = serialize($tmp_token);

		$clnt->redirectToAuth($tmp_token);
		/* you will probably need to have your twitter app configured to use/allow this callback_url
			at twitter.com/oauth as well! */
	}
	catch(OAuthException $ex)
	{
		echo 'Error during login: ' . htmlspecialchars($ex->getMessage());
	}
}
elseif($has_temp_token)
{
	/* we got called back from twitter (= step two) */

	try
	{
		$tmp_token = unserialize($_SESSION['temp_token']);
		unset($_SESSION['temp_token']);

		if(!isset($_GET['oauth_token']) || !isset($_GET['oauth_verifier']) ||
			$_GET['oauth_token'] != $tmp_token->getToken())
		{
			// this could happen if the user presses the back button in the browser e.g.
			echo 'Invalid request.';
			exit;
		}

		$clnt = new MyTwitterClient($_config['key'], $_config['secret'], $tmp_token);

		$authd_token = $clnt->getAccessToken($_GET['oauth_verifier']);

		/* done! your app now has access to the twitter API! */
		$_SESSION['authd_token'] = serialize($authd_token);

		/* so let's try it */
		header('Location: http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME']);
	}
	catch(OAuthException $ex)
	{
		echo 'Error during second step: ' . htmlspecialchars($ex->getMessage());
	}
}
elseif($has_access_token)
{
	/* looks like we have an access token. let's fetch some data */

	try
	{
		$authd_token = unserialize($_SESSION['authd_token']);

		$clnt = new MyTwitterClient($_config['key'], $_config['secret'], $authd_token);

		/* http://dev.twitter.com/doc/get/account/verify_credentials */

		$req = $clnt->createGetRequest('http://api.twitter.com/1/account/verify_credentials.json');
		$resp = $clnt->executeRequest($req);

		if($resp->getStatusCode() == 200)
		{
			$data = json_decode($resp->getBody());

			if(is_object($data))
			{
				echo htmlspecialchars('Hello ' . $data->screen_name . '! Your twitter account id is ' . $data->id . '!');
			}
		}
	}
	catch(OAuthException $ex)
	{
		echo 'Error communicating with twitter: ' . htmlspecialchars($ex->getMessage());
	}

	echo ' [<a href="?logout=1">Log Out</a>]';
}
else
{
	/* something went wrong, let's start over */
	session_destroy();
	header('Location: http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME']);
}
