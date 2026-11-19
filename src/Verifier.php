<?php

/*
 * This file is part of 88Pay Webhooks for PHP.
 *
 * Copyright (c) 2026 88 TECH GROUP S.A.S. All rights reserved.
 * Use is subject to the license in the LICENSE file.
 */

declare(strict_types=1);

namespace EightyEightPay\Webhooks;

use InvalidArgumentException;
use JsonException;
use LogicException;

/**
 * Verifies notifications (webhooks) sent by 88Pay.
 *
 * A notification is accepted only when:
 *  1. x-88pay-signature is the HMAC-SHA256 of "v1.<timestamp>.<raw body>".
 *  2. x-88pay-timestamp is within the allowed window (5 minutes by default).
 *  3. The Bearer token decrypts with AES-256-GCM and carries the same timestamp.
 */
final class Verifier
{
    public const DEFAULT_TOLERANCE_SECONDS = 300;
    public const DEFAULT_MAX_BODY_BYTES = 1048576;

    private const IV_BYTES = 12;
    private const TAG_BYTES = 16;
    private const MAX_TOKEN_CHARS = 4096;

    /** @var string */
    private $key;

    /** @var int */
    private $toleranceMs;

    /** @var int */
    private $maxBodyBytes;

    /**
     * @param string $notificationKeyHex Your notification key: 64 hexadecimal characters.
     * @param int    $toleranceSeconds   Maximum age (or clock skew) accepted for a notification.
     * @param int    $maxBodyBytes       Larger bodies are rejected before any other work.
     */
    public function __construct(
        #[\SensitiveParameter]
        string $notificationKeyHex,
        int $toleranceSeconds = self::DEFAULT_TOLERANCE_SECONDS,
        int $maxBodyBytes = self::DEFAULT_MAX_BODY_BYTES
    ) {
        if (PHP_INT_SIZE < 8) {
            throw new LogicException('88Pay webhooks require a 64-bit PHP build');
        }
        if (!extension_loaded('openssl')) {
            throw new LogicException('88Pay webhooks require the openssl extension');
        }

        $keyHex = trim($notificationKeyHex);
        if (preg_match('/\A[0-9A-Fa-f]{64}\z/', $keyHex) !== 1) {
            // The received value is never echoed.
            throw new InvalidArgumentException('The notification key must be 64 hexadecimal characters');
        }
        if ($toleranceSeconds < 1 || $toleranceSeconds > 86400) {
            throw new InvalidArgumentException('toleranceSeconds must be between 1 and 86400');
        }
        if ($maxBodyBytes < 1) {
            throw new InvalidArgumentException('maxBodyBytes must be positive');
        }

        $this->key = (string) hex2bin($keyHex);
        $this->toleranceMs = $toleranceSeconds * 1000;
        $this->maxBodyBytes = $maxBodyBytes;
    }

    /**
     * Verifies the request PHP is currently handling.
     *
     * Reads the raw body from php://input and the headers from $_SERVER, so it
     * behaves the same under Apache, PHP-FPM and the built-in server.
     *
     * @throws VerificationException
     */
    public function verifyFromGlobals(): Notification
    {
        $rawBody = file_get_contents('php://input', false, null, 0, $this->maxBodyBytes + 1);

        return $this->verify($rawBody === false ? '' : $rawBody, self::headersFromGlobals());
    }

    /**
     * Verifies a notification from its raw body and headers.
     *
     * @param string $rawBody The body exactly as received. Never a re-encoded array
     *                        or a framework's parsed input.
     * @param array<string, string|array<int, string>> $headers Any casing, $_SERVER keys
     *                        (HTTP_X_88PAY_SIGNATURE) or PSR-7 / Symfony value lists.
     * @param int|null $nowMs Current Unix time in milliseconds; for tests only.
     *
     * @throws VerificationException
     */
    public function verify(string $rawBody, array $headers, ?int $nowMs = null): Notification
    {
        if (strlen($rawBody) > $this->maxBodyBytes) {
            throw VerificationException::because(VerificationException::BODY_TOO_LARGE);
        }

        $headers = self::normalizeHeaders($headers);
        $timestamp = self::requireHeader($headers, 'x-88pay-timestamp');
        $signature = self::requireHeader($headers, 'x-88pay-signature');
        $authorization = self::requireHeader($headers, 'authorization');
        $requestId = self::header($headers, 'x-request-id');

        if (preg_match('/\A[1-9][0-9]{0,15}\z/', $timestamp) !== 1) {
            throw VerificationException::because(VerificationException::INVALID_TIMESTAMP);
        }
        $timestampMs = (int) $timestamp;

        $this->assertSignature($signature, 'v1.' . $timestamp . '.' . $rawBody);

        $now = $nowMs ?? (int) floor(microtime(true) * 1000);
        if (abs($now - $timestampMs) > $this->toleranceMs) {
            throw VerificationException::because(VerificationException::TIMESTAMP_OUT_OF_WINDOW);
        }

        $token = $this->decryptAuthorization($authorization, $timestampMs);

        return new Notification(
            self::decodeBody($rawBody),
            $rawBody,
            $timestampMs,
            $requestId !== null && preg_match('/\A[A-Za-z0-9-]{1,64}\z/', $requestId) === 1 ? $requestId : null,
            $token['transaction_id'],
            $token['transaction_amount']
        );
    }

    private function assertSignature(string $header, string $signedPayload): void
    {
        // 32 bytes in unpadded base64url are always 43 characters.
        if (preg_match('/\Av1=([A-Za-z0-9_-]{43})\z/', $header, $match) !== 1) {
            throw VerificationException::because(VerificationException::INVALID_SIGNATURE_FORMAT);
        }

        $provided = (string) base64_decode(strtr($match[1], '-_', '+/') . '=', true);
        $expected = hash_hmac('sha256', $signedPayload, $this->key, true);

        if (!hash_equals($expected, $provided)) {
            throw VerificationException::because(VerificationException::INVALID_SIGNATURE);
        }
    }

    /**
     * @return array{transaction_id: string, transaction_amount: string}
     */
    private function decryptAuthorization(string $header, int $timestampMs): array
    {
        if (
            strlen($header) > self::MAX_TOKEN_CHARS
            || preg_match('/\ABearer ([A-Za-z0-9+\/]+={0,2})\z/', $header, $match) !== 1
        ) {
            throw self::invalidAuthorization();
        }

        $raw = base64_decode($match[1], true);
        if ($raw === false || strlen($raw) <= self::IV_BYTES + self::TAG_BYTES) {
            throw self::invalidAuthorization();
        }

        // The tag is always sliced to its full 16 bytes, so a truncated tag cannot pass.
        $plaintext = openssl_decrypt(
            substr($raw, self::IV_BYTES, -self::TAG_BYTES),
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            substr($raw, 0, self::IV_BYTES),
            substr($raw, -self::TAG_BYTES)
        );
        if ($plaintext === false) {
            throw self::invalidAuthorization();
        }

        try {
            $payload = json_decode($plaintext, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw self::invalidAuthorization();
        }

        if (
            !is_array($payload)
            || ($payload['version'] ?? null) !== 1
            || ($payload['ts'] ?? null) !== $timestampMs
            || !is_string($payload['transaction_id'] ?? null)
            || !is_string($payload['transaction_amount'] ?? null)
        ) {
            throw self::invalidAuthorization();
        }

        return [
            'transaction_id' => $payload['transaction_id'],
            'transaction_amount' => $payload['transaction_amount'],
        ];
    }

    private static function invalidAuthorization(): VerificationException
    {
        return VerificationException::because(VerificationException::INVALID_AUTHORIZATION);
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeBody(string $rawBody): array
    {
        // Notifications are always JSON objects; a top-level list is rejected.
        if (strpos(ltrim($rawBody), '{') !== 0) {
            throw VerificationException::because(VerificationException::INVALID_BODY);
        }

        try {
            return json_decode($rawBody, true, 64, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (JsonException $e) {
            throw VerificationException::because(VerificationException::INVALID_BODY);
        }
    }

    /**
     * Lower-cases names and strips the HTTP_ / REDIRECT_HTTP_ prefixes of $_SERVER.
     *
     * @param array<mixed, mixed> $headers
     * @return array<string, list<string>>
     */
    private static function normalizeHeaders(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $name => $value) {
            if (!is_string($name)) {
                continue;
            }
            $name = preg_replace('/\A(redirect-)?http-/', '', strtolower(str_replace('_', '-', $name)));
            foreach (is_array($value) ? $value : [$value] as $item) {
                if (is_string($item)) {
                    $normalized[$name][] = $item;
                }
            }
        }

        return $normalized;
    }

    /**
     * @param array<string, list<string>> $headers
     */
    private static function requireHeader(array $headers, string $name): string
    {
        $value = self::header($headers, $name);
        if ($value === null) {
            throw VerificationException::because(VerificationException::MISSING_HEADER);
        }

        return $value;
    }

    /**
     * Every value is later checked against a strict, anchored pattern.
     *
     * @param array<string, list<string>> $headers
     */
    private static function header(array $headers, string $name): ?string
    {
        if (!isset($headers[$name])) {
            return null;
        }

        // A repeated identical value (HTTP_ and REDIRECT_HTTP_) is fine; different ones are not.
        $values = array_unique($headers[$name]);
        if (count($values) !== 1) {
            throw VerificationException::because(VerificationException::DUPLICATE_HEADER);
        }

        $value = trim((string) reset($values));

        return $value === '' ? null : $value;
    }

    /**
     * @return array<string, string>
     */
    private static function headersFromGlobals(): array
    {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (is_string($name) && is_string($value) && strpos($name, 'HTTP_') === 0) {
                $headers[$name] = $value;
            }
        }

        // Apache with CGI/FastCGI may hide Authorization from the usual key.
        if (!isset($headers['HTTP_AUTHORIZATION'])) {
            if (is_string($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null)) {
                $headers['HTTP_AUTHORIZATION'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
            } elseif (function_exists('getallheaders')) {
                foreach ((array) getallheaders() as $name => $value) {
                    if (is_string($name) && is_string($value) && strcasecmp($name, 'authorization') === 0) {
                        $headers['HTTP_AUTHORIZATION'] = $value;
                    }
                }
            }
        }

        return $headers;
    }

    /**
     * Keeps the key out of var_dump(), print_r() and debug toolbars.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'key' => '[redacted]',
            'toleranceSeconds' => intdiv($this->toleranceMs, 1000),
            'maxBodyBytes' => $this->maxBodyBytes,
        ];
    }

    /**
     * The verifier holds a secret; it must never reach a cache, session or queue.
     *
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('Verifier cannot be serialized');
    }

    /**
     * @param array<string, mixed> $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('Verifier cannot be unserialized');
    }
}
