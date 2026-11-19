<?php

/*
 * This file is part of 88Pay Webhooks for PHP.
 *
 * Copyright (c) 2026 88 TECH GROUP S.A.S. All rights reserved.
 * Use is subject to the license in the LICENSE file.
 */

declare(strict_types=1);

use EightyEightPay\Webhooks\VerificationException;
use EightyEightPay\Webhooks\Verifier;

require __DIR__ . '/../../src/VerificationException.php';
require __DIR__ . '/../../src/Notification.php';
require __DIR__ . '/../../src/Verifier.php';

try {
    $notification = (new Verifier((string) getenv('NOTIFICATION_KEY_HEX')))->verifyFromGlobals();
    echo $notification->transactionId();
} catch (VerificationException $e) {
    http_response_code(401);
    echo $e->getReason();
}
