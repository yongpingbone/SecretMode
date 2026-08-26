# ADR-002: Crypto protocol is a gated dependency

Status: Accepted for M0 evaluation, not production approval

## Decision

SecretMode evaluates `vodozemac = 0.10.0` for the 1:1 MVP. The dependency is pinned exactly during the spike.

SecretMode does not implement its own Double Ratchet and does not expose low-level cryptographic primitives to product code.

OpenMLS is deferred until group messaging is committed scope.

## Why vodozemac first

- pairwise Olm session model matches 1:1 MVP scope
- Rust implementation
- Apache-2.0 license
- independent audit history
- Double Ratchet properties are implemented by the dependency rather than by SecretMode

## Gate before production claims

The following are blockers before production E2EE wording or release:

1. Android arm64-v8a native build
2. JNI lifecycle and error handling
3. two-device identity + one-time key flow
4. authenticated peer identity verification
5. session persistence across process death
6. at least 1,000 bidirectional messages
7. dropped/out-of-order message tests
8. replay tests
9. corrupted state handling
10. cryptographic state destruction test
11. dependency/license review
12. external security review of integration assumptions

## Backend rule

The backend treats crypto headers as opaque bytes. It must not model Olm ratchet internals in database columns. This keeps transport storage protocol-neutral if SecretMode later migrates protocols.
