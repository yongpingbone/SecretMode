# ADR-009: Participant-authorized revoke initiation

Status: Proposed for M1 validation

## Context

A SecretMode participant must be able to request session destruction, but transport access is not authorization. A relay that can deliver packets must not be able to invent a valid revoke request, and a captured request must not remain usable forever.

Authenticated pairing already establishes the trusted Android device identity public keys for both participants. Those identity keys are the correct authority for participant-originated lifecycle requests. They are not the authority for final service state or lease issuance.

## Decision

A participant initiates revocation with a `participant_revoke_request` signed by that device's paired AndroidKeyStore identity key.

The canonical binary signing payload binds:

- protocol/domain version;
- random 128-bit `requestId`;
- `sessionId`;
- the verified relationship's 32-byte pairing transcript digest;
- requester device ID;
- requester identity-key fingerprint;
- `requestedAtMs` and `expiresAtMs`;
- participant-allowed revoke reason.

Allowed participant reasons are:

- `USER_REQUESTED`
- `DEVICE_REMOVED`
- `SECURITY_RESET`

`SESSION_EXPIRED` is intentionally not a participant request reason. Expiry is an authoritative service lifecycle condition.

The wire JSON is transport representation only. Signatures cover the canonical length-prefixed binary payload, not JSON serialization.

## Service verification order

Before accepting a participant revoke request, the service must fail closed unless all of the following are true:

1. The relationship exists and is currently `VERIFIED`.
2. The relationship transcript digest matches exactly.
3. The requester device ID is one of the verified relationship participants.
4. The requester's identity-key fingerprint matches the public key currently bound to that participant.
5. The ECDSA signature verifies under that paired identity public key.
6. Service time satisfies `requestedAtMs <= now < expiresAtMs`.
7. `requestId` has not already been accepted for that session/relationship.
8. The requester is authorized for the referenced `sessionId`.

Key change therefore invalidates the old authorization path automatically because the stored verified fingerprint/public key no longer matches.

## Authority split

A valid participant signature authorizes **initiation only**. It does not itself create an authoritative `SESSION_REVOKED` state event.

The intended flow is:

```text
participant identity key
  -> signed participant_revoke_request
  -> service verifies participant authorization
  -> service state machine enters REVOKING
  -> dedicated service state signer emits authoritative REVOKE_REQUESTED / SESSION_REVOKED events
  -> clients verify service-signed monotonic state before applying it
```

The relay may transport the request and resulting events, but relay possession does not grant participant signing authority or service state/lease signing authority.

## Replay and freshness

`requestId` is a one-time authorization nonce. A service-side accepted-request store or equivalent monotonic replay defense is required before this flow is production-complete.

`expiresAtMs` prevents a captured, otherwise-valid participant signature from becoming an indefinite kill switch. The production maximum request lifetime remains unspecified until service/network behavior is measured.

## Evidence required before checklist credit

Before marking `participant-authorized revoke request signature flow defined` complete, Android instrumentation must demonstrate at minimum:

- AndroidKeyStore identity signature verifies for the canonical request;
- the other participant's identity key cannot validate that signature;
- changing `sessionId` invalidates the signature;
- changing relationship transcript digest invalidates the signature;
- changing requester identity fingerprint invalidates the signature;
- changing revoke reason invalidates the signature;
- request binary fields are defensively copied.

This ADR does not accept the final service state/lease signer trust or key-rotation design.
