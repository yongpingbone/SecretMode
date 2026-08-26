# ADR-008: Backend-owned one-time pairing invite consumption

Status: Proposed for M1 validation

## Context

Authenticated pairing needs more than a client-side `ACCEPTED` state. If two devices race to accept the same invitation, a local state machine cannot prove that only one peer became authoritative. The backend storage boundary must make the pairing invitation globally single-use.

The storage layer is not a trust root for participant identity. Device signatures and the canonical pairing transcript remain the evidence for who is participating. Storage only decides whether a specific invitation is still available for consumption.

## Decision

Each invitation is stored under a globally unique 128-bit `pairingId` and binds:

- canonical `transcriptDigest`
- inviter device identifier
- inviter identity-key fingerprint
- server-observed validity window
- lifecycle status `ISSUED | CONSUMED | CANCELLED`
- the one authoritative consumer after successful consumption

The application calls one database function to consume an invitation. Inside that function PostgreSQL:

1. acquires an exclusive row lock with `SELECT ... FOR UPDATE`;
2. only after the lock is acquired, reads fresh database server time;
3. re-checks transcript digest, lifecycle state, and `issuedAt <= now < expiresAt`;
4. performs the single transition to `CONSUMED` while the same lock is held.

There is no application-layer `SELECT available` followed later by an unrelated `UPDATE consumed`.

The first successful call records the consumer device identifier, consumer identity-key fingerprint, and server timestamp. Every later consumer returns no mutation.

Client-supplied time is intentionally absent from the consume function. Expiry is authoritative only from database server time, and time is sampled after lock acquisition so a waiter cannot begin before expiry, remain blocked, and then consume with stale time after expiry.

## Concurrency rule

CI must cover two independent connections where:

- consumer A acquires the invite row lock and consumes it, but deliberately delays commit;
- consumer B attempts to consume while A still owns the lock;
- after A commits, B must acquire/read the committed row, observe `CONSUMED`, and fail.

CI must also cover a holder that locks but does not consume an invitation until the invitation expires. A waiting consumer that started while the invite was valid must acquire the row only after expiry, sample fresh server time, and fail without mutating the invitation.

## Security boundary

This storage function does **not** authenticate device signatures by itself. A future service endpoint must verify the invitee's authenticated pairing message before calling the storage mutation.

The relay is not implicitly allowed to:

- fabricate inviter or invitee signatures;
- mark a relationship `VERIFIED`;
- sign authoritative session state events or leases merely because it can write transport data.

Those service-signing boundaries remain separate M1 gates.

## Retry semantics

The storage primitive is deliberately strict: only the first transition from `ISSUED` to `CONSUMED` returns success. Replays, including a retry from the same device, return no mutation. If the API later wants idempotent user-facing retries, it must model and authenticate that behavior explicitly rather than weakening the storage invariant.

## Evidence required before checklist credit

Do not mark the M1 invite-consumption gate complete until CI demonstrates:

- first consume succeeds;
- serial replay fails;
- wrong transcript digest fails without burning the invite;
- expired invite fails;
- not-yet-valid invite fails;
- cancelled invite fails;
- two-consumer lock race yields exactly one winner;
- a consumer blocked until after expiry still fails.

This ADR and the PostgreSQL spike are not a deployed production backend.
