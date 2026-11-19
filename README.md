# 88Pay Webhooks for PHP

Verify the notifications (webhooks) 88Pay sends to your `notification_url`.

Every notification is checked three ways before your code sees it:

1. **Signature**: `X-88Pay-Signature` must be the HMAC-SHA256 of the timestamp and the exact body.
2. **Freshness**: `X-88Pay-Timestamp` must be within 5 minutes of your server clock.
3. **Authorization**: the `Bearer` token must decrypt with your key (AES-256-GCM) and match the timestamp.

No dependencies. PHP 7.4 or newer, 64-bit, with the `openssl` extension.

## Installation

```bash
composer require 88pay/webhooks
```

## Usage

Your notification key is in the 88Pay dashboard settings, labelled **Notification Key**.
Sandbox and production have different keys. Keep it in an environment variable or secret manager, never in code.

### Plain PHP

```php
use EightyEightPay\Webhooks\Verifier;
use EightyEightPay\Webhooks\VerificationException;

$verifier = new Verifier(getenv('EIGHTY_EIGHT_PAY_NOTIFICATION_KEY'));

try {
    $notification = $verifier->verifyFromGlobals();
} catch (VerificationException $e) {
    error_log('88Pay notification rejected: ' . $e->getReason());
    http_response_code(401);
    exit;
}

// Trusted from here on.
$notification->transactionId(); // "sess_00000000-0000-4000-8000-000000000000"
$notification->status();        // "COMPLETED"
$notification->amount();        // "20.00"
$notification->body();          // full decoded body

http_response_code(200);
```

### Laravel

```php
public function __invoke(Request $request)
{
    $verifier = new Verifier(config('services.88pay.notification_key'));

    try {
        $notification = $verifier->verify($request->getContent(), $request->headers->all());
    } catch (VerificationException $e) {
        Log::warning('88Pay notification rejected', ['reason' => $e->getReason()]);
        abort(401);
    }

    // ...
    return response()->noContent();
}
```

### Symfony

```php
$notification = $verifier->verify($request->getContent(), $request->headers->all());
```

### PSR-7 (Slim, Laminas, ...)

```php
$notification = $verifier->verify((string) $request->getBody(), $request->getHeaders());
```

## The most common mistake

Pass the body **exactly as it was received**. Do not decode it and encode it again,
and do not use `$_POST` or a framework's parsed input:

```php
// Wrong: json_encode() escapes "/" and unicode differently, so the signature no longer matches.
$verifier->verify(json_encode($request->all()), $headers);

// Right
$verifier->verify($request->getContent(), $headers);
```

## The `Notification` object

| Method | Returns |
|---|---|
| `transactionId()` | Transaction id from the encrypted token. Present in every notification type. |
| `amount()` | Transaction amount from the encrypted token, as a string. |
| `status()` | `transaction_status` from the body, or `null`. |
| `get($field, $default = null)` | Any field of the body. |
| `body()` | The decoded body as an array. |
| `rawBody()` | The body exactly as received. |
| `timestampMs()` | When 88Pay signed it, in Unix milliseconds. |
| `requestId()` | `X-Request-Id`. Every delivery attempt has its own id. |

## Rejection reasons

`VerificationException::getReason()` returns one of:

| Reason | What to check |
|---|---|
| `missing_header` | A header did not reach PHP. With Apache and PHP-FPM, see below. |
| `duplicate_header` | A proxy sent the same header twice with different values. |
| `invalid_timestamp` | `X-88Pay-Timestamp` was modified before reaching your code. |
| `invalid_signature_format` | `X-88Pay-Signature` was modified before reaching your code. |
| `invalid_signature` | Wrong key, or the body is not the raw body (see above). |
| `timestamp_out_of_window` | Your server clock is off, or the notification is a replay. |
| `invalid_authorization` | The `Authorization` header was modified or belongs to another key. |
| `body_too_large` | The body exceeds the limit (1 MiB by default). |
| `invalid_body` | The signed body is not a JSON object. |

Log the reason, answer `401`, and never send the reason or the request back to the caller.

### Apache: `Authorization` does not reach PHP

Some Apache + CGI/FastCGI setups drop the header. Add this to `.htaccess`:

```apache
CGIPassAuth On
```

## Options

```php
new Verifier(
    $key,
    300,     // toleranceSeconds: accepted age / clock skew (1 to 86400)
    1048576  // maxBodyBytes: larger bodies are rejected before any work
);
```

Keep your server clock synced (NTP). Do not raise the tolerance to work around a wrong clock.

## Good practices

- **Be idempotent.** The same transaction can be notified more than once, each time newly signed.
  Process each `transactionId()` and `status()` pair once.
- **Answer fast.** Return `200` after verifying and storing the notification; do slow work afterwards.
- **Only use verified data.** Read values from the `Notification`, not from the raw request.
- **Protect the key.** The `Verifier` hides it from `var_dump()` and `print_r()` and refuses to be serialized.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Proprietary. You may install and use this package, unmodified, to integrate with 88Pay.
Modifying or redistributing it is not allowed. See [LICENSE](LICENSE).
