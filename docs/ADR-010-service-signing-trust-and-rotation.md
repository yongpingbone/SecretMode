# ADR-010: Authoritative service signer trust and rotation

Status: M1 candidate pending client verification evidence

## Decision

Authoritative SecretMode session-state events and display/session leases are signed by a dedicated service signing authority. Participant device identity keys do not sign authoritative service state, and the relay/storage tier does not acquire signing authority merely because it receives, stores, or forwards protocol objects.

The trust chain is:

```text
app-pinned offline root public key
  -> root-signed short-lived service keyset
  -> scoped online leaf signing key
  -> authoritative STATE_EVENT or LEASE artifact
```

The offline root private key is not present on relay hosts, general API hosts, databases, or routine online signer workers. Clients pin root public-key SPKI material under explicit `rootKeyId` values. A root-signed keyset is accepted only after canonical-signature verification, time-window validation, monotonic keyset-version checks, and same-version digest consistency checks.

## Leaf-key scope

Each online leaf key has exactly one scope:

- `STATE_EVENT`: authoritative `SESSION_ACTIVATED`, `REVOKE_REQUESTED`, `SESSION_REVOKED`, and `SESSION_PURGED` state artifacts.
- `LEASE`: bounded session/display leases.

A state-event key cannot validate a lease and a lease key cannot validate a state event. The keyset binds each leaf `keyId`, P-256 SPKI public key, scope, validity window, status, and optional disable time. The M1 baseline uses P-256 with `SHA256withECDSA`, matching Android's existing verification support.

## Keyset anti-rollback

Every accepted keyset carries a strictly positive `keysetVersion` and a canonical SHA-256 digest. The client persists the highest accepted version plus its digest as security state.

Clients reject:

- a keyset below the app-bundled minimum version;
- a keyset below the highest version already accepted on that installation;
- different keyset contents presented under the same already-accepted version;
- a keyset whose root signature does not verify under a pinned `rootKeyId`;
- a keyset outside its issuance/expiry window.

Re-presenting the exact same signed keyset version and digest is idempotent. After process death, the persisted version/digest floor must be restored before accepting another keyset.

The app-bundled minimum version and keyset expiry bound replay on a fresh installation. Runtime anti-rollback is stronger because the highest accepted version/digest survives process death. Local device-time compromise is not treated as a substitute for keyset-version rollback protection.

## Online leaf rotation

Normal leaf rotation is staged:

1. Generate the next leaf in the dedicated signer boundary.
2. Offline-root sign a higher-version keyset containing the current and next scoped leaf keys.
3. Distribute the keyset through any relay/cache path; transport is untrusted.
4. After clients can learn the new key, switch authoritative signing to the next leaf.
5. Publish another higher-version keyset marking the old leaf `RETIRED` with a disable time, then destroy the old online private key.
6. Retain the old public-key metadata long enough to validate historical artifacts issued before retirement.

For a `RETIRED` key, a client may validate an artifact only when the artifact's signed issuance time predates the key's disable time and remains inside the leaf validity window. Normal retirement therefore requires destruction of the retired private key so it cannot be used to create backdated artifacts later.

## Compromise and revocation

`REVOKED` is different from normal retirement. Once a higher-version root-signed keyset marks a leaf `REVOKED`, clients reject artifacts from that key regardless of claimed historical issuance time. Already-persisted monotonic lifecycle state is not silently rolled backward; the client must synchronize replacement authoritative state from a non-revoked signer.

A compromised relay cannot manufacture this revocation or undo it because it cannot produce the offline-root keyset signature. A malicious relay can still delay or withhold valid objects, which is an availability attack rather than signing authority.

## Root rotation

Root-key rotation is deliberately not delegated to an online relay. V1 uses staged application releases:

1. An app release pins both the current root and the next root under distinct `rootKeyId` values.
2. The service moves to a higher-version keyset signed by the next root.
3. A later app release removes the old root pin after migration is complete.

A keyset signed by an unknown root is rejected even when its JSON/protocol shape is otherwise valid. Emergency root compromise therefore requires an application trust-anchor update; this is intentionally slower than online leaf rotation but avoids creating a second online meta-root.

## Relay boundary

The relay may transport ciphertext, participant-signed requests, root-signed keysets, service-signed state events, and service-signed leases. It may cache and deduplicate them. It MUST NOT hold an offline-root private key or online leaf signing key.

The client does not trust a `signingKeyId` simply because it arrived from the relay. The ID must resolve to a leaf in a currently accepted root-signed keyset, with the correct scope, status, time window, and valid artifact signature. A relay-generated root, leaf, keyset, or artifact therefore fails closed.

## Persistence and deployment boundary

`highest_service_keyset_version` and the digest of that accepted keyset are security state and must survive process death and ordinary app restart. The production persistence implementation may share the encrypted security-state boundary with lifecycle metadata, but deleting UI cache must not erase this anti-rollback floor.

This ADR accepts the trust architecture only after client tests prove root pinning, scope isolation, leaf validity/status rules, keyset rollback/equivocation rejection, process-death restoration, staged root rotation, and rejection of relay-generated trust material. It does not place production private keys in this repository and does not claim that a production signer service has been deployed.
