# SecretMode

Private 1:1 Android messaging prototype focused on secure session revocation, Android Bubble UX, and cryptographic erasure.

## Status

**M0 Foundation / Crypto Spike**

This repository is intentionally separate from any third-party messaging app. SecretMode does not modify, scrape, or impersonate another app's UI and does not require AccessibilityService or `SYSTEM_ALERT_WINDOW`.

## MVP scope

- Android 11+ (`minSdk 30`)
- 1:1 text-only messaging
- Single active device per user
- Android Notification Bubble with Activity fallback
- No AccessibilityService
- No application overlay permission
- No plaintext in notifications, logs, analytics, saved instance state, or persistent app state
- Protocol-neutral encrypted envelopes
- Crypto integration spike before production E2EE claims
- Session revocation + lease model
- Cryptographic erasure as the deletion guarantee

## Milestones

1. **M0 Foundation + Crypto Spike**
   - Android shell builds
   - Bubble capability detection + fallback
   - secure UI state rules
   - Rust/JNI skeleton
   - vodozemac `>= 0.10.0` evaluation
2. **M1 Pairing**
3. **M2 Secure 1:1 Messaging**
4. **M3 Revocation + Lease**
5. **M4 Security Hardening**
6. **M5 Two-device acceptance**

## Security rule

Private plaintext MUST NOT participate in Android state restoration.

See `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, and `docs/ADR/` before adding protocol or storage code.
