<?php

/*
 * This file is part of 88Pay Webhooks for PHP.
 *
 * Copyright (c) 2026 88 TECH GROUP S.A.S. All rights reserved.
 * Use is subject to the license in the LICENSE file.
 */

declare(strict_types=1);

namespace EightyEightPay\Webhooks;

use RuntimeException;

/**
 * Thrown when an incoming notification cannot be trusted.
 *
 * The message is intentionally generic and never contains header values,
 * body content or key material, so it is safe to write to your logs.
 * Do not echo it back to the caller: answer with a plain 401 instead.
 */
final class VerificationException extends RuntimeException
{
    public const MISSING_HEADER = 'missing_header';
    public const DUPLICATE_HEADER = 'duplicate_header';
    public const INVALID_TIMESTAMP = 'invalid_timestamp';
    public const TIMESTAMP_OUT_OF_WINDOW = 'timestamp_out_of_window';
    public const INVALID_SIGNATURE_FORMAT = 'invalid_signature_format';
    public const INVALID_SIGNATURE = 'invalid_signature';
    public const INVALID_AUTHORIZATION = 'invalid_authorization';
    public const BODY_TOO_LARGE = 'body_too_large';
    public const INVALID_BODY = 'invalid_body';

    private const MESSAGES = [
        self::MISSING_HEADER => 'A required 88Pay header is missing',
        self::DUPLICATE_HEADER => 'A 88Pay header was sent more than once',
        self::INVALID_TIMESTAMP => 'The x-88pay-timestamp header is not valid',
        self::TIMESTAMP_OUT_OF_WINDOW => 'The notification timestamp is outside the allowed window',
        self::INVALID_SIGNATURE_FORMAT => 'The x-88pay-signature header is not valid',
        self::INVALID_SIGNATURE => 'The notification signature does not match',
        self::INVALID_AUTHORIZATION => 'The authorization token could not be verified',
        self::BODY_TOO_LARGE => 'The notification body is larger than allowed',
        self::INVALID_BODY => 'The notification body is not a JSON object',
    ];

    /** @var string */
    private $reason;

    private function __construct(string $reason)
    {
        parent::__construct(self::MESSAGES[$reason]);
        $this->reason = $reason;
    }

    /**
     * @internal
     */
    public static function because(string $reason): self
    {
        return new self($reason);
    }

    /**
     * Machine readable reason, one of the class constants.
     */
    public function getReason(): string
    {
        return $this->reason;
    }
}
