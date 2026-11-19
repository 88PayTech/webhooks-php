# Changelog

All notable changes to this package are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/).

## 1.0.0

### Added

- `Verifier::verify()` and `Verifier::verifyFromGlobals()` check the HMAC-SHA256 signature,
  the timestamp window and the AES-256-GCM authorization token of 88Pay notifications.
- `Notification` exposes the verified body, transaction id, amount, status and request id.
- `VerificationException::getReason()` returns a machine-readable rejection reason.
