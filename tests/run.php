<?php

/*
 * This file is part of 88Pay Webhooks for PHP.
 *
 * Copyright (c) 2026 88 TECH GROUP S.A.S. All rights reserved.
 * Use is subject to the license in the LICENSE file.
 */

declare(strict_types=1);

/*
 * Dependency-free test runner: php tests/run.php
 *
 * tests/vectors.json was produced by the signer 88Pay uses in production,
 * with random keys and fictitious transactions.
 */

use EightyEightPay\Webhooks\Notification;
use EightyEightPay\Webhooks\VerificationException;
use EightyEightPay\Webhooks\Verifier;

require __DIR__ . '/../src/VerificationException.php';
require __DIR__ . '/../src/Notification.php';
require __DIR__ . '/../src/Verifier.php';

$failures = 0;
$passed = 0;

function check(string $name, callable $test): void
{
    global $failures, $passed;
    try {
        $test();
        $passed++;
    } catch (Throwable $e) {
        $failures++;
        fwrite(STDERR, "FAIL {$name}: {$e->getMessage()}\n");
    }
}

function assertTrue(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function expectReason(string $reason, callable $call): void
{
    try {
        $call();
    } catch (VerificationException $e) {
        assertTrue($e->getReason() === $reason, "expected {$reason}, got {$e->getReason()}");
        return;
    }
    throw new RuntimeException("expected {$reason}, nothing was thrown");
}

/** Signs a body with the vector's key and timestamp, reusing its authorization token. */
function resign(array $vector, string $rawBody): array
{
    $headers = $vector['headers'];
    $timestamp = $headers['x-88pay-timestamp'];
    $mac = hash_hmac('sha256', "v1.{$timestamp}.{$rawBody}", hex2bin($vector['key']), true);
    $headers['x-88pay-signature'] = 'v1=' . rtrim(strtr(base64_encode($mac), '+/', '-_'), '=');

    return $headers;
}

$vectors = json_decode((string) file_get_contents(__DIR__ . '/vectors.json'), true, 512, JSON_THROW_ON_ERROR);
$v = $vectors[0];
$verifier = new Verifier($v['key']);
$verify = static function (string $body, array $headers, ?int $now = null) use ($verifier, $v): Notification {
    return $verifier->verify($body, $headers, $now ?? $v['nowMs']);
};

// Valid notifications, every header style a framework can produce.

foreach ($vectors as $vector) {
    check("accepts {$vector['name']}", static function () use ($vector): void {
        $n = (new Verifier($vector['key']))->verify($vector['rawBody'], $vector['headers'], $vector['nowMs']);
        assertTrue($n->transactionId() === $vector['expected']['transactionId'], 'transaction id');
        assertTrue($n->amount() === $vector['expected']['amount'], 'amount');
        assertTrue($n->rawBody() === $vector['rawBody'], 'raw body');
        assertTrue($n->body() === json_decode($vector['rawBody'], true), 'decoded body');
        assertTrue($n->requestId() === $vector['headers']['x-request-id'], 'request id');
        assertTrue($n->timestampMs() === (int) $vector['headers']['x-88pay-timestamp'], 'timestamp');
    });
}

check('reads status and fields', static function () use ($verify, $v): void {
    $n = $verify($v['rawBody'], $v['headers']);
    assertTrue($n->status() === 'COMPLETED', 'status');
    assertTrue($n->get('transaction_currency') === 'BRL', 'field');
    assertTrue($n->get('missing', 'default') === 'default', 'default');
});

check('accepts $_SERVER style headers', static function () use ($verify, $v): void {
    $server = ['REQUEST_METHOD' => 'POST', 'REQUEST_TIME' => 1];
    foreach ($v['headers'] as $name => $value) {
        $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
    }
    $verify($v['rawBody'], $server);
});

check('accepts PSR-7 / Symfony value lists in any casing', static function () use ($verify, $v): void {
    $headers = [];
    foreach ($v['headers'] as $name => $value) {
        $headers[ucwords($name, '-')] = [$value];
    }
    $verify($v['rawBody'], $headers);
});

check('accepts Authorization only under REDIRECT_HTTP_AUTHORIZATION', static function () use ($verify, $v): void {
    $headers = $v['headers'];
    $headers['REDIRECT_HTTP_AUTHORIZATION'] = $headers['authorization'];
    unset($headers['authorization']);
    $verify($v['rawBody'], $headers);
});

check('accepts the same value repeated under two names', static function () use ($verify, $v): void {
    $headers = $v['headers'];
    $headers['REDIRECT_HTTP_AUTHORIZATION'] = $headers['authorization'];
    $verify($v['rawBody'], $headers);
});

check('accepts a timestamp slightly in the future (clock skew)', static function () use ($verify, $v): void {
    $verify($v['rawBody'], $v['headers'], (int) $v['headers']['x-88pay-timestamp'] - 60000);
});

check('drops a malformed x-request-id instead of returning it', static function () use ($verify, $v): void {
    $headers = $v['headers'];
    $headers['x-request-id'] = "<script>alert(1)</script>";
    assertTrue($verify($v['rawBody'], $headers)->requestId() === null, 'request id kept');
});

// Body integrity.

check('rejects a modified body', static function () use ($verify, $v): void {
    expectReason(VerificationException::INVALID_SIGNATURE, static function () use ($verify, $v): void {
        $verify(str_replace('20.00', '2000.00', $v['rawBody']), $v['headers']);
    });
});

check('rejects a re-encoded body (json_decode + json_encode)', static function () use ($vectors): void {
    $vector = $vectors[2];
    $reencoded = json_encode(json_decode($vector['rawBody'], true));
    assertTrue($reencoded !== $vector['rawBody'], 'vector must change when re-encoded');
    expectReason(VerificationException::INVALID_SIGNATURE, static function () use ($vector, $reencoded): void {
        (new Verifier($vector['key']))->verify($reencoded, $vector['headers'], $vector['nowMs']);
    });
});

check('rejects trailing whitespace added to the body', static function () use ($verify, $v): void {
    expectReason(VerificationException::INVALID_SIGNATURE, static function () use ($verify, $v): void {
        $verify($v['rawBody'] . "\n", $v['headers']);
    });
});

check('rejects a body larger than the limit', static function () use ($v): void {
    expectReason(VerificationException::BODY_TOO_LARGE, static function () use ($v): void {
        (new Verifier($v['key'], 300, 64))->verify($v['rawBody'], $v['headers'], $v['nowMs']);
    });
});

check('rejects a signed body that is not a JSON object', static function () use ($verify, $v): void {
    foreach (['[1,2]', '"text"', '{"broken":', ''] as $body) {
        expectReason(VerificationException::INVALID_BODY, static function () use ($verify, $v, $body): void {
            $verify($body, resign($v, $body));
        });
    }
});

// Signature.

check('rejects the wrong key', static function () use ($v): void {
    expectReason(VerificationException::INVALID_SIGNATURE, static function () use ($v): void {
        (new Verifier(str_repeat('ab', 32)))->verify($v['rawBody'], $v['headers'], $v['nowMs']);
    });
});

check('rejects a malformed signature header', static function () use ($verify, $v): void {
    $valid = $v['headers']['x-88pay-signature'];
    $bad = [substr($valid, 3), 'v2=' . substr($valid, 3), $valid . '=', $valid . 'A', 'v1=' . str_repeat('+', 43), " v1 = x"];
    foreach ($bad as $signature) {
        expectReason(VerificationException::INVALID_SIGNATURE_FORMAT, static function () use ($verify, $v, $signature): void {
            $verify($v['rawBody'], ['x-88pay-signature' => $signature] + $v['headers']);
        });
    }
});

check('rejects a signature of the right shape but wrong value', static function () use ($verify, $v): void {
    expectReason(VerificationException::INVALID_SIGNATURE, static function () use ($verify, $v): void {
        $verify($v['rawBody'], ['x-88pay-signature' => 'v1=' . str_repeat('A', 43)] + $v['headers']);
    });
});

// Timestamp.

check('rejects a changed timestamp', static function () use ($verify, $v): void {
    expectReason(VerificationException::INVALID_SIGNATURE, static function () use ($verify, $v): void {
        $headers = $v['headers'];
        $headers['x-88pay-timestamp'] = (string) ((int) $headers['x-88pay-timestamp'] + 1);
        $verify($v['rawBody'], $headers);
    });
});

check('rejects malformed timestamps', static function () use ($verify, $v): void {
    foreach (['abc', '-1795008429703', '1.795008429703E+12', '01795008429703', '1795008429703.0', '99999999999999999'] as $ts) {
        expectReason(VerificationException::INVALID_TIMESTAMP, static function () use ($verify, $v, $ts): void {
            $verify($v['rawBody'], ['x-88pay-timestamp' => $ts] + $v['headers']);
        });
    }
});

check('rejects an old notification (replay)', static function () use ($verify, $v): void {
    expectReason(VerificationException::TIMESTAMP_OUT_OF_WINDOW, static function () use ($verify, $v): void {
        $verify($v['rawBody'], $v['headers'], (int) $v['headers']['x-88pay-timestamp'] + 301000);
    });
});

check('honours a custom tolerance', static function () use ($v): void {
    $verifier = new Verifier($v['key'], 30);
    expectReason(VerificationException::TIMESTAMP_OUT_OF_WINDOW, static function () use ($verifier, $v): void {
        $verifier->verify($v['rawBody'], $v['headers'], (int) $v['headers']['x-88pay-timestamp'] + 31000);
    });
});

// Authorization token.

check('rejects a tampered authorization token', static function () use ($verify, $v): void {
    $raw = base64_decode(substr($v['headers']['authorization'], 7));
    $raw[20] = chr(ord($raw[20]) ^ 1);
    expectReason(VerificationException::INVALID_AUTHORIZATION, static function () use ($verify, $v, $raw): void {
        $verify($v['rawBody'], ['authorization' => 'Bearer ' . base64_encode($raw)] + $v['headers']);
    });
});

check('rejects a truncated authentication tag', static function () use ($verify, $v): void {
    $raw = base64_decode(substr($v['headers']['authorization'], 7));
    expectReason(VerificationException::INVALID_AUTHORIZATION, static function () use ($verify, $v, $raw): void {
        $verify($v['rawBody'], ['authorization' => 'Bearer ' . base64_encode(substr($raw, 0, -4))] + $v['headers']);
    });
});

check('rejects a token issued for another timestamp', static function () use ($verify, $v): void {
    // Valid signature and fresh timestamp, but the token says another moment.
    $headers = $v['headers'];
    $key = hex2bin($v['key']);
    $iv = random_bytes(12);
    $plain = json_encode(['version' => 1, 'transaction_id' => 'x', 'transaction_amount' => '1', 'ts' => 1]);
    $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    $headers['authorization'] = 'Bearer ' . base64_encode($iv . $cipher . $tag);
    expectReason(VerificationException::INVALID_AUTHORIZATION, static function () use ($verify, $v, $headers): void {
        $verify($v['rawBody'], $headers);
    });
});

check('rejects malformed authorization headers', static function () use ($verify, $v): void {
    $token = substr($v['headers']['authorization'], 7);
    foreach ([$token, 'Basic ' . $token, 'Bearer ' . $token . '!', 'Bearer ' . str_repeat('A', 5000), 'Bearer QUJD'] as $value) {
        expectReason(VerificationException::INVALID_AUTHORIZATION, static function () use ($verify, $v, $value): void {
            $verify($v['rawBody'], ['authorization' => $value] + $v['headers']);
        });
    }
});

// Headers.

check('rejects missing or empty headers', static function () use ($verify, $v): void {
    foreach (['x-88pay-timestamp', 'x-88pay-signature', 'authorization'] as $name) {
        foreach ([false, true] as $empty) {
            $headers = $v['headers'];
            if ($empty) {
                $headers[$name] = '   ';
            } else {
                unset($headers[$name]);
            }
            expectReason(VerificationException::MISSING_HEADER, static function () use ($verify, $v, $headers): void {
                $verify($v['rawBody'], $headers);
            });
        }
    }
});

check('rejects conflicting values for the same header', static function () use ($verify, $v): void {
    $headers = $v['headers'];
    $headers['X-88PAY-SIGNATURE'] = 'v1=' . str_repeat('A', 43);
    expectReason(VerificationException::DUPLICATE_HEADER, static function () use ($verify, $v, $headers): void {
        $verify($v['rawBody'], $headers);
    });
});

// Secrets never leak.

check('rejects invalid keys without echoing them', static function (): void {
    foreach (['', 'secret', str_repeat('g', 64), str_repeat('a', 63), str_repeat('a', 66)] as $key) {
        try {
            new Verifier($key);
            throw new RuntimeException('accepted an invalid key');
        } catch (InvalidArgumentException $e) {
            assertTrue($key === '' || strpos($e->getMessage(), $key) === false, 'key echoed');
        }
    }
});

check('accepts a key with surrounding whitespace and upper case', static function () use ($v): void {
    (new Verifier("  " . strtoupper($v['key']) . "\n"))->verify($v['rawBody'], $v['headers'], $v['nowMs']);
});

check('keeps the key out of var_dump, print_r and var_export', static function () use ($v, $verifier): void {
    ob_start();
    var_dump($verifier);
    $dump = ob_get_clean() . print_r($verifier, true);
    assertTrue(strpos($dump, '[redacted]') !== false, 'not redacted');
    assertTrue(strpos($dump, $v['key']) === false && strpos($dump, hex2bin($v['key'])) === false, 'key leaked');
});

check('refuses to be serialized', static function () use ($verifier): void {
    try {
        serialize($verifier);
    } catch (LogicException $e) {
        return;
    }
    throw new RuntimeException('serialized');
});

check('exception messages never contain request data', static function () use ($verify, $v): void {
    try {
        $verify('{"a":1}', $v['headers']);
    } catch (VerificationException $e) {
        foreach (array_merge([$v['key'], '{"a":1}'], array_values($v['headers'])) as $secret) {
            assertTrue(strpos($e->getMessage(), $secret) === false, 'message leaks request data');
        }
        return;
    }
    throw new RuntimeException('nothing thrown');
});

// verifyFromGlobals() through a real HTTP server.

check('verifyFromGlobals() works behind the built-in web server', static function () use ($v): void {
    // Fresh notification built like the production signer (proven compatible above).
    $key = hex2bin($v['key']);
    $timestamp = (string) (int) floor(microtime(true) * 1000);
    $iv = random_bytes(12);
    $token = json_encode(['version' => 1, 'transaction_id' => 'sess_live', 'transaction_amount' => '20.00', 'ts' => (int) $timestamp]);
    $cipher = openssl_encrypt($token, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    $mac = hash_hmac('sha256', "v1.{$timestamp}.{$v['rawBody']}", $key, true);
    $headerLines = [
        'Content-Type: application/json',
        'X-Request-Id: 00000000-0000-4000-8000-000000000000',
        "X-88Pay-Timestamp: {$timestamp}",
        'X-88Pay-Signature: v1=' . rtrim(strtr(base64_encode($mac), '+/', '-_'), '='),
        'Authorization: Bearer ' . base64_encode($iv . $cipher . $tag),
    ];

    $port = random_int(20000, 60000);
    $process = proc_open(
        [PHP_BINARY, '-S', "127.0.0.1:{$port}", __DIR__ . '/fixtures/endpoint.php'],
        [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes,
        null,
        ['NOTIFICATION_KEY_HEX' => $v['key']]
    );
    try {
        $post = static function (string $body) use ($port, $headerLines) {
            return @file_get_contents("http://127.0.0.1:{$port}/", false, stream_context_create(['http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headerLines),
                'content' => $body,
                'ignore_errors' => true,
            ]]));
        };
        $response = false;
        for ($i = 0; $i < 50 && $response === false; $i++) {
            usleep(100000);
            $response = $post($v['rawBody']);
        }
        assertTrue($response === 'sess_live', 'server answered: ' . var_export($response, true));
        assertTrue($post($v['rawBody'] . ' ') === VerificationException::INVALID_SIGNATURE, 'tampered body accepted');
    } finally {
        proc_terminate($process);
        proc_close($process);
    }
});

echo "{$passed} passed, {$failures} failed\n";
exit($failures === 0 ? 0 : 1);
