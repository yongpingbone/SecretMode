# SecretMode Architecture v0.2

## Product boundary

SecretMode is an independent private messaging app. It must not impersonate, modify, scrape, or depend on another messaging app.

The preferred in-context UX is Android Notification Bubble. If bubbles are unavailable or blocked, SecretMode falls back to a normal Activity.

## M0 topology

```text
Foreground app
    |
    | Android SystemUI / Bubble windowing
    v
SecretMode BubbleActivity
    |
    +-- secure UI policy
    +-- SessionEngine (future)
    +-- SecureSession interface (future)
    +-- encrypted storage (future)
    |
    v
Transport / backend (future)
```

## Explicitly excluded

- AccessibilityService
- SYSTEM_ALERT_WINDOW
- TYPE_APPLICATION_OVERLAY
- touch interception over another app
- plaintext notification content
- plaintext logs / analytics
- plaintext Android SavedState
- cloud backup of private session material

## Android baseline

- minSdk 30
- targetSdk 37
- AGP 9.3.0
- JDK 17
- Notification Bubble first, Activity fallback
- BubbleActivity is `allowEmbedded=true` and `resizeableActivity=true`

## Crypto decision gate

M0 evaluates vodozemac 0.10.0 for pairwise Olm sessions.

The app MUST NOT claim production-grade E2EE until the crypto integration gate passes:

1. Android arm64 build
2. Kotlin/Rust JNI
3. A/B identity creation
4. authenticated pairing design
5. outbound + inbound session creation
6. 1,000 message roundtrip
7. out-of-order / dropped / replay behavior
8. process-death serialization/restore
9. state destruction prevents future app decryption
10. third-party license review

OpenMLS is deferred until group messaging becomes committed scope.

## Session lifecycle target

```text
CREATING -> ACTIVE -> REVOKING -> REVOKED -> PURGED
```

`REVOKED -> ACTIVE` is always invalid.

## Remote revoke target semantics

Online peers should observe revocation quickly. Offline peers cannot be physically modified remotely, so SecretMode uses authoritative server state plus expiring display/session leases. A revoked server state can never issue a new lease.

## Storage target

Deletion means cryptographic erasure, not a promise that every NAND cell is physically overwritten immediately.

The storage design must account for database files, WAL, journal, caches, and wrapped session material as one security boundary.
