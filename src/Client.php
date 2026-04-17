<?php

namespace TrafficOrchestrator;

/**
 * Official PHP client for Traffic Orchestrator API.
 *
 * Usage:
 *   $client = new \TrafficOrchestrator\Client('https://api.trafficorchestrator.com/api/v1', 'sk_live_xxxxx');
 *   $result = $client->validateLicense('LK-xxxx-xxxx', 'example.com');
 */
class Client
{
    const VERSION = '2.0.0';

    private $baseUrl;
    private $apiKey;
    private $timeout;
    private $retries;

    public function __construct($baseUrl = 'https://api.trafficorchestrator.com/api/v1', $apiKey = null, $timeout = 10, $retries = 2)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->apiKey  = $apiKey;
        $this->timeout = $timeout;
        $this->retries = $retries;
    }

    // ── Core: License Validation ──────────────────────────────────────────

    /**
     * Validate a license key against the API server.
     */
    public function validateLicense($token, $domain)
    {
        return $this->request('POST', '/validate', [
            'token'  => $token,
            'domain' => $domain,
        ]);
    }

    /**
     * Verify license token offline using Ed25519 signature.
     * Requires sodium extension (built-in since PHP 7.2).
     */
    public function verifyOffline($token, $publicKeyBase64, $domain = null)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return ['valid' => false, 'error' => 'Invalid token format'];
        }

        $header = json_decode($this->base64UrlDecode($parts[0]), true);
        $payload = json_decode($this->base64UrlDecode($parts[1]), true);
        $signature = $this->base64UrlDecode($parts[2]);

        if (!isset($header['alg']) || $header['alg'] !== 'EdDSA') {
            return ['valid' => false, 'error' => 'Algorithm not supported'];
        }

        // Verify signature
        $publicKey = base64_decode($publicKeyBase64);
        $message = $parts[0] . '.' . $parts[1];

        if (!sodium_crypto_sign_verify_detached($signature, $message, $publicKey)) {
            return ['valid' => false, 'error' => 'Invalid signature'];
        }

        // Verify expiration
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return ['valid' => false, 'error' => 'Token expired'];
        }

        // Verify domain
        if ($domain !== null && isset($payload['dom']) && is_array($payload['dom'])) {
            $match = false;
            foreach ($payload['dom'] as $d) {
                if (strpos($domain, $d) !== false) {
                    $match = true;
                    break;
                }
            }
            if (!$match) {
                return ['valid' => false, 'error' => 'Domain mismatch'];
            }
        }

        return ['valid' => true, 'payload' => $payload];
    }

    // ── License Management (requires API key) ────────────────────────────

    /** List all licenses for the authenticated user. */
    public function listLicenses()
    {
        $data = $this->request('GET', '/portal/licenses');
        return $data['licenses'] ?? [];
    }

    /** Create a new license. */
    public function createLicense($appName, $domain = null, $planId = null)
    {
        $body = ['appName' => $appName];
        if ($domain !== null) $body['domain'] = $domain;
        if ($planId !== null) $body['planId'] = $planId;
        return $this->request('POST', '/portal/licenses', $body);
    }

    /** Rotate a license key (revoke old, generate new). */
    public function rotateLicense($licenseId)
    {
        return $this->request('POST', "/portal/licenses/{$licenseId}/rotate");
    }

    /** Add a domain to a license. */
    public function addDomain($licenseId, $domain)
    {
        return $this->request('POST', "/portal/licenses/{$licenseId}/domains", [
            'domain' => $domain,
        ]);
    }

    /** Remove a domain from a license. */
    public function removeDomain($licenseId, $domain)
    {
        return $this->request('DELETE', "/portal/licenses/{$licenseId}/domains", [
            'domain' => $domain,
        ]);
    }

    /** Delete (revoke) a license. */
    public function deleteLicense($licenseId)
    {
        return $this->request('DELETE', "/portal/licenses/{$licenseId}");
    }

    // ── Usage & Analytics ────────────────────────────────────────────────

    /** Get current usage statistics. */
    public function getUsage()
    {
        return $this->request('GET', '/portal/stats');
    }

    // ── Health ───────────────────────────────────────────────────────────

    /** Check API health status. */
    public function healthCheck()
    {
        return $this->request('GET', '/health');
    }

    // ── Internal ─────────────────────────────────────────────────────────

    private function request($method, $path, $body = null)
    {
        $url     = $this->baseUrl . $path;
        $headers = ['Content-Type: application/json'];
        if ($this->apiKey) {
            $headers[] = 'Authorization: Bearer ' . $this->apiKey;
        }

        $lastError = null;
        for ($attempt = 0; $attempt <= $this->retries; $attempt++) {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

            if ($method === 'POST' && $body !== null) {
                $data = json_encode($body);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            } elseif ($method === 'DELETE') {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
                if ($body !== null) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
                }
            }

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($response === false) {
                $lastError = 'cURL error';
                if ($attempt < $this->retries) {
                    usleep(min(1000000 * pow(2, $attempt), 5000000));
                }
                continue;
            }

            $result = json_decode($response, true);

            if ($httpCode >= 400 && $httpCode < 500) {
                return $result ?? ['valid' => false, 'error' => "HTTP $httpCode"];
            }

            if ($httpCode >= 200 && $httpCode < 300) {
                return $result;
            }

            $lastError = "HTTP $httpCode";
            if ($attempt < $this->retries) {
                usleep(min(1000000 * pow(2, $attempt), 5000000));
            }
        }

        return ['valid' => false, 'error' => $lastError ?? 'Request failed'];
    }

    private function base64UrlDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}

