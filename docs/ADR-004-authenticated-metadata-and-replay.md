# ADR-004: Authenticate message metadata before replay decisions

Status: Accepted for the M0 protocol foundation.

## Context

The relay/backend is not trusted with plaintext and may be compromised. It can duplicate, delay, reorder, drop, or modify transport envelopes. Olm protects the encrypted plaintext, but it does not make cleartext routing fields in the outer envelope trustworthy.

A naive `sequence > lastSequence` check is also invalid because SecretMode must tolerate ordinary out-of-order delivery.

## Decision

Security-critical message metadata is duplicated inside the Olm plaintext using `protocol/authenticated-message.schema.json`. The outer envelope contains routing mirrors only.

The receive path is ordered as follows:

1. Parse and size-bound the outer envelope. Treat its identifiers, sequence, and timestamp as untrusted routing hints.
2. Resolve the candidate local session and reject immediately if it is missing, destroyed, or already revoked. A revoked state always wins over message delivery.
3. Decrypt the Olm ciphertext.
4. Parse the authenticated inner message.
5. Require exact equality between inner and outer `sessionId`, `messageId`, `senderDeviceId`, `sequence`, and `createdAt`. Any mismatch rejects the envelope.
6. Re-check authoritative local session state before rendering if asynchronous work allowed a revoke/state transition to race with decryption.
7. Feed only the authenticated inner sequence to a replay window keyed by `(sessionId, senderDeviceId)`.
8. Render the body only after the replay window accepts it.

The M0 replay window is 128 sequence numbers wide. It accepts unseen out-of-order messages inside the window, rejects duplicate sequence numbers, and rejects messages older than the window.

## Persistence requirement

Before production use, replay-window state must be persisted atomically with the corresponding decrypt/session state. Restarting a process must not silently reset replay protection. M0 currently proves the window algorithm separately from the future encrypted persistence layer.

## Consequences

The backend cannot authoritatively decide replay status. An outer sequence number can accelerate routing/indexing but never advances client replay state by itself. Gaps are legal, so dropped messages do not stall a session. Revocation/session state remains a stronger gate than replay acceptance.
