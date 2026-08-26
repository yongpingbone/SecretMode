# SecretMode Architecture v0.3

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
    +-- encrypted storage / Android Keystore boundary
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
- compileSdk / targetSdk 36 for the reproducible M0 toolchain
- AGP 9.3.0
- JDK 17
- Notification Bubble first, Activity fallback
- BubbleActivity is `allowEmbedded=true` and `resizeableActivity=true`

API 37 is not required by any M0 feature. The project should only raise compile/target SDK when the SDK platform is available in the reproducible CI toolchain and a product or policy requirement justifies the change.

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

## Storage / cryptographic-erasure boundary

M0 introduces an Android Keystore storage primitive before any real Olm pickle is persisted by the product. A session-state blob is encrypted with AES-256-GCM using a non-exportable Android Keystore key. The session identifier is bound as authenticated additional data, and the Keystore alias uses a SHA-256 fingerprint rather than the raw session identifier.

The M0 emulator probe must prove all of the following on the Android Keystore provider:

1. state encrypted under the live session key decrypts correctly
2. deleting the Keystore entry removes app decryptability for the old ciphertext
3. recreating a new key under the same derived alias still cannot authenticate/decrypt ciphertext created by the destroyed key
4. cleanup removes the replacement probe key

This establishes cryptographic erasure of app decryptability, not physical overwriting of every NAND cell. Production storage still has to treat encrypted database rows, WAL/journal files, caches, replay-window state, and wrapped Olm session material as one lifecycle boundary.
