# ADR-005: Monotonic revocation and expiring leases

Status: M0 candidate

## Decision

SecretMode session lifecycle is monotonic:

```text
CREATING -> ACTIVE -> REVOKING -> REVOKED -> PURGED
```

A client persists the highest verified `stateVersion` and accepted event IDs. A verified event whose state version is stale, duplicated, or attempts an invalid backward transition is rejected. `REVOKED -> ACTIVE` and every transition out of `PURGED` are invalid even when an attacker presents a numerically higher state version.

Revocation begins at `REVOKING`. Once that state is reached, no new display/session lease may be issued or accepted. Existing leases are bounded by expiry and are rejected immediately by a client that already knows the session is no longer ACTIVE.

A signed lease binds at minimum `leaseId`, `sessionId`, `holderDeviceId`, `stateVersion`, `issuedAt`, `expiresAt`, and a nonce. Clients reject expired leases, wrong session/device bindings, stale state versions, and future state versions they have not verified.

## Signature boundary

This ADR defines the signed payload shapes and the lifecycle policy, not the final trust root. Session events and leases enter the lifecycle engine only after signature verification. The exact signing suite, signing authority, key discovery, and key-change UX depend on the authenticated pairing design and remain an M0 gate.

The relay/backend alone MUST NOT become an implicit signing trust root merely because it transported an event. This preserves the threat-model boundary while pairing is still under review.

## Offline limitation

SecretMode cannot remotely erase a completely offline peer. Authoritative revocation prevents renewal; an offline peer may retain a previously issued lease only until its expiry. On reconnect, the client must synchronize the highest verified terminal state before rendering and then destroy local decryptability.

The production lease TTL remains deliberately unspecified until Android background/network tests establish a defensible value.

## Persistence requirement

`highest_state_version`, terminal lifecycle state, accepted event IDs or an equivalent replay-resistant representation, and lease metadata are security state. They must survive process death whenever the corresponding cryptographic session survives. Purging the session must destroy these records as part of the same lifecycle boundary.
