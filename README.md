# traffic-orchestrator-php

Official PHP SDK for [Traffic Orchestrator](https://trafficorchestrator.com) — license validation, management, and analytics.

📖 [API Reference](https://trafficorchestrator.com/docs#api) · [SDK Guides](https://trafficorchestrator.com/docs/sdk/php) · [OpenAPI Spec](https://api.trafficorchestrator.com/api/v1/openapi.json)

## Install

```bash
composer require traffic-orchestrator/sdk
```

## Quick Start

```php
use TrafficOrchestrator\Client;

$to = new Client();
$result = $to->validateLicense('LK-xxxx', 'example.com');

if ($result->valid) {
    echo "Plan: " . $result->planId;
}
```

## Authenticated Usage

```php
$to = new Client(['apiKey' => getenv('TO_API_KEY')]);
$licenses = $to->listLicenses();
```

## API Methods

### Core License Operations

| Method | Auth | Description |
| --- | --- | --- |
| `validateLicense($token, $domain)` | No | Validate a license key |
| `verifyOffline($token, $publicKey, $domain)` | No | Ed25519 offline verification |
| `listLicenses()` | Yes | List all licenses |
| `createLicense($options)` | Yes | Create a new license |
| `rotateLicense($licenseId)` | Yes | Rotate license key |
| `deleteLicense($licenseId)` | Yes | Revoke a license |
| `getUsage()` | Yes | Get usage statistics |
| `getAnalytics($days)` | Yes | Get detailed analytics |
| `healthCheck()` | No | Check API health |

### Portal & Enterprise Methods

| Method | Auth | Description |
| --- | --- | --- |
| `addDomain($licenseId, $domain)` | Yes | Add domain to license |
| `removeDomain($licenseId, $domain)` | Yes | Remove domain from license |
| `getDomains($licenseId)` | Yes | Get license domains |
| `updateLicenseStatus($id, $status)` | Yes | Suspend/reactivate license |
| `listApiKeys()` | Yes | List API keys |
| `createApiKey($name, $scopes)` | Yes | Create API key |
| `deleteApiKey($keyId)` | Yes | Delete API key |
| `getDashboard()` | Yes | Full dashboard overview |

## Retry (Guzzle Middleware)

```php
$to = new Client([
    'apiKey' => getenv('TO_API_KEY'),
    'timeout' => 5,
    'retries' => 3,  // Retry on 5xx with backoff
]);
```

## Multi-Environment

```php
// Production (default)
$to = new Client(['apiKey' => getenv('TO_API_KEY')]);

// Staging
$to = new Client([
    'apiKey' => getenv('TO_API_KEY_DEV'),
    'apiUrl' => 'https://api-staging.trafficorchestrator.com/api/v1',
]);
```

## Offline Verification (Enterprise)

Validate licenses locally without API calls using Ed25519 JWT signatures:

```php
$to = new Client([
    'publicKey' => getenv('TO_PUBLIC_KEY'),
]);
$result = $to->verifyOffline($licenseToken);
if ($result->valid) {
    echo "Plan: " . $result->planId;
}
```

## Requirements

- PHP 8.0+
- Guzzle 7.x

## License

MIT
