<?php
/**
 * Traffic Orchestrator PHP SDK Tests
 * Self-contained test suite — no Composer or PHPUnit needed.
 * Run: php test_client.php
 */

require_once __DIR__ . '/client.php';

$passed = 0;
$failed = 0;
$errors = [];

function assert_true($condition, $label) {
    global $passed, $failed, $errors;
    if ($condition) {
        $passed++;
        echo "  ✓ $label\n";
    } else {
        $failed++;
        $errors[] = $label;
        echo "  ✗ FAIL: $label\n";
    }
}

function assert_equals($expected, $actual, $label) {
    assert_true($expected === $actual, "$label (expected: " . var_export($expected, true) . ", got: " . var_export($actual, true) . ")");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Constructor
// ═══════════════════════════════════════════════════════════════════════════════
echo "\n=== Constructor ===\n";

$client = new TrafficOrchestrator\Client();
$ref = new ReflectionClass($client);
$prop = $ref->getProperty('baseUrl');
$prop->setAccessible(true);
assert_equals('https://api.trafficorchestrator.com/api/v1', $prop->getValue($client), 'default baseUrl');

$custom = new TrafficOrchestrator\Client('https://custom.example.com');
assert_equals('https://custom.example.com', $prop->getValue($custom), 'custom baseUrl');

// ═══════════════════════════════════════════════════════════════════════════════
// base64UrlDecode (private method via reflection)
// ═══════════════════════════════════════════════════════════════════════════════
echo "\n=== base64UrlDecode ===\n";

$method = $ref->getMethod('base64UrlDecode');
$method->setAccessible(true);

$decoded = $method->invoke($client, base64_encode('hello world'));
assert_equals('hello world', $decoded, 'standard base64 decode');

// URL-safe chars
$input = rtrim(strtr(base64_encode('test data!'), '+/', '-_'), '=');
$decoded = $method->invoke($client, $input);
assert_equals('test data!', $decoded, 'URL-safe base64 decode');

// ═══════════════════════════════════════════════════════════════════════════════
// verifyOffline — token format
// ═══════════════════════════════════════════════════════════════════════════════
echo "\n=== verifyOffline — format checks ===\n";

$result = $client->verifyOffline('not-a-valid-token', 'key');
assert_true(!$result['valid'], 'rejects token without 3 parts');
assert_equals('Invalid token format', $result['error'], 'error message for invalid format');

$result = $client->verifyOffline('a.b.c.d', 'key');
assert_true(!$result['valid'], 'rejects token with 4 parts');

// ═══════════════════════════════════════════════════════════════════════════════
// verifyOffline — algorithm check
// ═══════════════════════════════════════════════════════════════════════════════
echo "\n=== verifyOffline — algorithm check ===\n";

function b64url($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

$header_rs256 = b64url(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
$payload = b64url(json_encode(['exp' => time() + 3600]));
$token_rs256 = $header_rs256 . '.' . $payload . '.fakesig';
$result = $client->verifyOffline($token_rs256, base64_encode(str_repeat('x', 32)));
assert_true(!$result['valid'], 'rejects non-EdDSA algorithm');
assert_equals('Algorithm not supported', $result['error'], 'correct error for wrong alg');

// ═══════════════════════════════════════════════════════════════════════════════
// verifyOffline — Ed25519 signature verification
// ═══════════════════════════════════════════════════════════════════════════════
echo "\n=== verifyOffline — Ed25519 ===\n";

// Generate a real Ed25519 keypair using sodium
$keypair = sodium_crypto_sign_keypair();
$publicKey = sodium_crypto_sign_publickey($keypair);
$secretKey = sodium_crypto_sign_secretkey($keypair);
$publicKeyB64 = base64_encode($publicKey);

function makeToken($claims, $secretKey) {
    $header = b64url(json_encode(['alg' => 'EdDSA', 'typ' => 'JWT']));
    $payload = b64url(json_encode($claims));
    $message = $header . '.' . $payload;
    $signature = sodium_crypto_sign_detached($message, $secretKey);
    return $message . '.' . b64url($signature);
}

// Valid token
$token = makeToken(['exp' => time() + 3600, 'dom' => ['example.com']], $secretKey);
$result = $client->verifyOffline($token, $publicKeyB64, 'example.com');
assert_true($result['valid'], 'valid token accepted');
assert_true(isset($result['payload']), 'payload returned');

// Valid token, no domain check
$result = $client->verifyOffline($token, $publicKeyB64);
assert_true($result['valid'], 'valid token without domain check');

// Expired token
$token_expired = makeToken(['exp' => time() - 3600, 'dom' => ['example.com']], $secretKey);
$result = $client->verifyOffline($token_expired, $publicKeyB64);
assert_true(!$result['valid'], 'expired token rejected');
assert_equals('Token expired', $result['error'], 'correct error for expired');

// Domain mismatch
$token_domains = makeToken(['exp' => time() + 3600, 'dom' => ['allowed.com']], $secretKey);
$result = $client->verifyOffline($token_domains, $publicKeyB64, 'evil.com');
assert_true(!$result['valid'], 'domain mismatch rejected');
assert_equals('Domain mismatch', $result['error'], 'correct error for domain mismatch');

// Domain match with subdomain
$result = $client->verifyOffline($token_domains, $publicKeyB64, 'sub.allowed.com');
assert_true($result['valid'], 'subdomain match accepted');

// Invalid signature (different keypair)
$keypair2 = sodium_crypto_sign_keypair();
$publicKey2B64 = base64_encode(sodium_crypto_sign_publickey($keypair2));
$result = $client->verifyOffline($token, $publicKey2B64);
assert_true(!$result['valid'], 'wrong key rejected');
assert_equals('Invalid signature', $result['error'], 'correct error for invalid sig');

// ═══════════════════════════════════════════════════════════════════════════════
// verifyOffline — payload contents
// ═══════════════════════════════════════════════════════════════════════════════
echo "\n=== verifyOffline — payload contents ===\n";

$claims = ['exp' => time() + 3600, 'dom' => ['a.com', 'b.com'], 'plan' => 'PROFESSIONAL', 'iss' => 'trafficorchestrator.com'];
$token = makeToken($claims, $secretKey);
$result = $client->verifyOffline($token, $publicKeyB64);
assert_true($result['valid'], 'token with extra claims is valid');
assert_equals('PROFESSIONAL', $result['payload']['plan'], 'plan claim preserved');
assert_equals(['a.com', 'b.com'], $result['payload']['dom'], 'dom claim preserved');
assert_equals('trafficorchestrator.com', $result['payload']['iss'], 'iss claim preserved');

// ═══════════════════════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════════════════════
echo "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo " Results: $passed passed, $failed failed\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

if ($failed > 0) {
    echo "\nFailed tests:\n";
    foreach ($errors as $e) {
        echo "  • $e\n";
    }
    exit(1);
}

exit(0);
