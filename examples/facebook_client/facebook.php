<?php
/*
 * This example code is hereby released into Public Domain.
 */

use proauth;

$_config = array(
	/* get your own app key + secret at http://www.facebook.com/developers */
	'key' => '', /* App ID, not API key! */
	'secret' => ''
);


/* include OAuth 2.0 client library */
require_once dirname(__FILE__) . '/../../lib/oauth/OAuth2Client.php';


/* utility methods for obtaining an access token. */


/* this wrapper returns an OAuth2CurlClient client instance that is not (yet)
	initialized with an access token (=anonymous). We use it while we fetch the token. */
function getAnonClient()
{
	global $_config;

	$clnt = new OAuth2CurlClient();
	$clnt->setEndpoints('https://graph.facebook.com/oauth/authorize', 'https://graph.facebook.com/oauth/access_token');
	$clnt->setClientId($_config['key'], $_config['secret']);
	/* $clnt->setAccessSecretType(new OAuth2SignatureHmacSha256()); Facebook does not support token secrets */

	return $clnt;
}


/* your webserver needs to make sure that HTTP_HOST is safe to use. */
$redirect_url = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'] . '?step2=1';


/* code for the actual example "page" */


if(isset($_GET['login']))
{
	/* step 1, user clicked "login with facebook link, redirect them to FB */
	$clnt = getAnonClient();

	$obt = $clnt->getAccessTokenObtainer('web_server');
	$obt->setRedirectUrl($redirect_url);

	$obt->webFlowRedirect();
}
elseif(isset($_GET['step2']))
{
	/* step 2, user authed our app at FB, so let's get the access token */
	$clnt = getAnonClient();

	$obt = $clnt->getAccessTokenObtainer('web_server');
	$obt->setRedirectUrl($redirect_url); // yes, this steps needs the redirect_url as well!

	if($obt->webServerDidUserAuthorize())
	{
		/* we should save the access token to the database or something
			so we can use it later to make calls and stuff */
		$req = $clnt->createGetRequest('https://graph.facebook.com/me', array('access_token' => $clnt->getAccessToken()->getToken()));
		$resp = $clnt->executeRequest($req);

		if($resp->getStatusCode() == 200)
		{
			$json = json_decode($resp->getBody());

			echo '<pre>' . htmlspecialchars(print_r($json, true)) . '</pre>';
		}
	}
	else
	{
		/* if they clicked "deny access", this will happen */
		echo 'WHY DON\'T YOU LIKE ME!!!!';
	}
}
else
{
	echo '<a href="?login=1">Log in with Facebook</a>';
}
