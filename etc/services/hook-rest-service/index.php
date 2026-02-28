<?php

$respondWithJsonAndExit = function (array $responsePayload): void {
	$responsePayloadString = json_encode($responsePayload);

	echo $responsePayloadString;

	file_put_contents('php://stdout', sprintf("Responding with: %s\n", $responsePayloadString));

	exit;
};

if ($_SERVER['REQUEST_URI'] === '/reject/with-33-percent-chance') {
	if (rand(0, 2) === 0) {
		$respondWithJsonAndExit([
			'id' => 'rejecting-unlucky-ones',
			'action' => 'reject',
			'responseStatusCode' => 403,
			'rejectionErrorCode' => 'M_FORBIDDEN',
			'rejectionErrorMessage' => 'Rejecting it via a hook delivered from a REST service',
		]);
	}

	$respondWithJsonAndExit([
		'id' => 'allowing-lucky-ones',
		'action' => 'pass.unmodified',
	]);
}

if ($_SERVER['REQUEST_URI'] === '/reject/forbidden') {
	$respondWithJsonAndExit([
		'id' => 'rejection-response-hook',
		'action' => 'reject',
		'responseStatusCode' => 403,
		'rejectionErrorCode' => 'M_FORBIDDEN',
		'rejectionErrorMessage' => 'Rejecting it via a hook delivered from a REST service',
	]);
}

if ($_SERVER['REQUEST_URI'] === '/inject-something-into-request') {
	$respondWithJsonAndExit([
		'id' => 'injection-request-hook',
		'action' => 'pass.modifiedRequest',
		"injectJSONIntoRequest" => [
			'customKey' => 'value',
		],
		'injectHeadersIntoRequest' => [
			'X-Custom-Header' => 'Header-Value',
		],
	]);
}

if ($_SERVER['REQUEST_URI'] === '/inject-something-into-response') {
	$respondWithJsonAndExit([
		'id' => 'injection-response-hook',
		'action' => 'pass.modifiedResponse',
		"injectJSONIntoResponse" => [
			'customKey' => 'value',
		],
		'injectHeadersIntoResponse' => [
			'X-Custom-Header' => 'Header-Value',
		],
	]);
}

if ($_SERVER['REQUEST_URI'] === '/respond-with-something') {
	// We could read the request (and possibly response) information here,
	// and act depending on that.
	//
	// See how we do it for the `/dump` handler for an example.
	$respondWithJsonAndExit([
		'id' => 'respond-directly',
		'action' => 'respond',
		"responseStatusCode" => 200,
		'responsePayload' => [
			'message' => 'This response is coming from the REST service',
		],
	]);
}


// Reject room invitations sent to the admin user. Set ADMIN_MATRIX_USER_ID in the environment
// (e.g. @admin:your.server) to the full MXID to protect. If unset, all invites pass through.
if (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === '/reject-invite-to-admin') {
	$payload = file_get_contents('php://input');
	$data = json_decode($payload, true);
	$adminUserId = getenv('ADMIN_MATRIX_USER_ID');
	if ($adminUserId === false) {
		$adminUserId = '';
	}
	$isInviteToAdmin = false;
	if ($adminUserId !== '' && isset($data['request']['path']) && isset($data['request']['payload'])) {
		$path = $data['request']['path'];
		if (str_ends_with($path, '/invite')) {
			$body = json_decode($data['request']['payload'], true);
			if (is_array($body) && isset($body['user_id']) && $body['user_id'] === $adminUserId) {
				$isInviteToAdmin = true;
			}
		}
	}
	if ($isInviteToAdmin) {
		$respondWithJsonAndExit([
			'id' => 'reject-invite-to-admin',
			'action' => 'reject',
			'responseStatusCode' => 403,
			'rejectionErrorCode' => 'M_FORBIDDEN',
			'rejectionErrorMessage' => 'Inviting the admin user to rooms is not allowed.',
		]);
	}
	$respondWithJsonAndExit([
		'id' => 'allow-invite',
		'action' => 'pass.unmodified',
	]);
}

if ($_SERVER['REQUEST_URI'] === '/dump') {
	$payload = file_get_contents('php://input');

	file_put_contents('php://stdout', sprintf("Request: %s\n", print_r($_SERVER, true)));
	file_put_contents('php://stdout', sprintf("Payload: %s\n", $payload));

	// The payload may or may not be JSON.
	// So errors below may mean malformed JSON input, or (in rare cases) something different than JSON.
	$json = json_decode($payload);
	if (json_last_error() != JSON_ERROR_NONE) {
		file_put_contents('php://stdout', sprintf(
			"Payload parsing error (%s): %s\n",
			json_last_error(),
			json_last_error_msg(),
		));
	} else {
		file_put_contents('php://stdout', "Payload JSON parsing: OK\n");
	}

	$respondWithJsonAndExit([
		'id' => 'passed-after-dump',
		'action' => 'pass.unmodified',
	]);
}

$respondWithJsonAndExit([
	'id' => 'default',
	'action' => 'pass.unmodified',
]);
