<?php

/*
 * This file is part of 88Pay Webhooks for PHP.
 *
 * Copyright (c) 2026 88 TECH GROUP S.A.S. All rights reserved.
 * Use is subject to the license in the LICENSE file.
 */

declare(strict_types=1);

namespace EightyEightPay\Webhooks;

/**
 * A notification whose signature and authorization token were verified.
 *
 * Instances are only created by Verifier, so holding one means the content
 * came from 88Pay and was not modified on the way.
 */
final class Notification
{
    /** @var array<string, mixed> */
    private $body;

    /** @var string */
    private $rawBody;

    /** @var int */
    private $timestampMs;

    /** @var string|null */
    private $requestId;

    /** @var string */
    private $signedTransactionId;

    /** @var string */
    private $signedAmount;

    /**
     * @internal Use Verifier::verify() or Verifier::verifyFromGlobals().
     *
     * @param array<string, mixed> $body
     */
    public function __construct(
        array $body,
        string $rawBody,
        int $timestampMs,
        ?string $requestId,
        string $signedTransactionId,
        string $signedAmount
    ) {
        $this->body = $body;
        $this->rawBody = $rawBody;
        $this->timestampMs = $timestampMs;
        $this->requestId = $requestId;
        $this->signedTransactionId = $signedTransactionId;
        $this->signedAmount = $signedAmount;
    }

    /**
     * The decoded JSON body.
     *
     * @return array<string, mixed>
     */
    public function body(): array
    {
        return $this->body;
    }

    /**
     * The body exactly as it was received.
     */
    public function rawBody(): string
    {
        return $this->rawBody;
    }

    /**
     * A single field of the body, or $default when it is not present.
     *
     * @param mixed $default
     * @return mixed
     */
    public function get(string $field, $default = null)
    {
        return array_key_exists($field, $this->body) ? $this->body[$field] : $default;
    }

    /**
     * Transaction id carried inside the encrypted authorization token.
     *
     * It is present in every notification type, whatever the shape of the body.
     */
    public function transactionId(): string
    {
        return $this->signedTransactionId;
    }

    /**
     * Transaction amount carried inside the encrypted authorization token.
     */
    public function amount(): string
    {
        return $this->signedAmount;
    }

    /**
     * Value of transaction_status in the body, when present.
     */
    public function status(): ?string
    {
        $status = $this->get('transaction_status');

        return is_string($status) ? $status : null;
    }

    /**
     * Moment 88Pay signed the notification, in Unix milliseconds.
     */
    public function timestampMs(): int
    {
        return $this->timestampMs;
    }

    /**
     * Value of the x-request-id header. Each delivery attempt has its own id.
     */
    public function requestId(): ?string
    {
        return $this->requestId;
    }
}
