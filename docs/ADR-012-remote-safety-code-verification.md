# ADR-012: Remote safety-code human verification

Status: Accepted for M1 design; implementation disabled

## Decision

SecretMode may support a remote human-verification mode for cases where the two intended participants cannot scan a QR directly from each other's device screens. Remote verification is a separate mode, not a fallback or compatibility shortcut for the in-person flow defined by ADR-007.

The remote mode stays disabled until its derivation test vectors, mode-aware acknowledgment gate, two-device UX, and negative tests are implemented and accepted. This ADR does not add a production verification method or change the current `VERIFIED` gate.

## Security goal

Remote safety-code comparison is intended to detect a man-in-the-middle substitution of the paired device identities when the participants compare the complete code over an independently authenticated channel outside SecretMode.

It does not prove a person's civil or real-world identity. It also does not protect against a compromised endpoint, an attacker who controls both SecretMode and the comparison channel, coercion, shoulder surfing, screen photography, or a participant intentionally approving a mismatched code.

The UI must make the independent-channel assumption explicit. A call, video call, or another already-authenticated channel may be used. Comparing the code only by sending it through the same SecretMode session being verified is invalid.

## Verification modes must not mix

Human verification becomes explicitly mode-aware before remote verification can be enabled.

- `IN_PERSON` requires the existing role-separated pair of `IN_PERSON_QR_SCAN` and `IN_PERSON_PEER_CONFIRM` acknowledgments.
- `REMOTE_SAFETY_CODE` requires two valid `REMOTE_SAFETY_CODE_COMPARE` acknowledgments, one from each distinct pairing role/device.
- an in-person acknowledgment and a remote acknowledgment can never combine to satisfy `VERIFIED`
- two acknowledgments from the same device or role can never satisfy `VERIFIED`
- the selected mode is included in the signed acknowledgment domain/payload so a valid acknowledgment cannot be reinterpreted under another mode

Implementation must therefore refactor the current verifier deliberately. Merely adding a new enum value to the existing method set is prohibited.

## Safety-code derivation v1

Both devices derive the same display code locally from the already-verified final canonical pairing transcript. No relay-provided value participates in the derivation.

1. serialize the final transcript using the locked canonical transcript encoding
2. compute

   `seed = SHA-256("SecretMode remote safety code v1\0" || canonical_final_transcript)`

3. take the first 25 bytes of `seed`
4. clear the most-significant bit of the first byte, yielding a uniformly distributed unsigned 199-bit value
5. interpret those 25 bytes as one unsigned big-endian integer
6. convert that integer to decimal and left-pad with zeroes to exactly 60 digits
7. render the full value as 12 groups of 5 digits

Because the canonical final transcript already binds the pairing ID, inviter/invitee roles, device IDs, identity public keys, nonces, and expiry context, any change to the paired identity material produces a different code. Domain separation prevents this digest from being confused with another protocol hash.

The displayed 60 digits are a human representation only. The verifier never accepts a prefix, suffix, abbreviated fingerprint, fuzzy match, edit distance, or partial group match. Users must compare the complete code.

## Human acknowledgment

After a participant has compared the complete code over the independent channel, the UI requires an explicit action equivalent to `Entire code matches`.

Each device then signs its own remote-verification acknowledgment with its already-bound AndroidKeyStore device identity key. The signed payload binds at minimum:

- acknowledgment protocol/domain version
- pairing ID
- final transcript digest
- verification mode `REMOTE_SAFETY_CODE`
- method `REMOTE_SAFETY_CODE_COMPARE`
- verifier role
- verifier device ID
- verification timestamp

The relationship remains unverified until both distinct role-bound acknowledgments are received and validated. The relay may transport acknowledgments but cannot create, replace, or authorize them.

## UX requirements before enablement

The remote screen must:

- label the feature as remote safety-code comparison, never as automatic identity verification
- show all 60 digits with unambiguous fixed grouping and tabular/monospaced numerals where practical
- instruct both participants to compare the entire code over an independent authenticated channel
- require an explicit confirmation on each device
- show mismatch/cancel as a safe terminal or retry state, never auto-approve
- avoid putting the code in notifications, analytics, crash reports, or logs
- avoid copy-to-clipboard and share shortcuts by default; if such a feature is ever added, it requires a separate privacy review
- clear or cover the code when the verification screen leaves the foreground and use Android secure-window protections where applicable

Accessibility review must ensure the complete code can be read in deterministic group order without silently skipping groups.

## Replay, expiry, and key change

Remote acknowledgments are valid only for the active final pairing transcript and before its expiry. A consumed/expired invite or a fresh pairing transcript requires a fresh code and fresh acknowledgments.

Any device identity-key change invalidates the previous relationship verification and produces a new transcript and safety code. Previous remote acknowledgments do not migrate to the new key.

A stored screenshot or remembered old code cannot authorize a new pairing because the signed acknowledgments are bound to the new pairing ID and final transcript digest.

## Service boundary

The relay is transport only. It must not derive an alternate authoritative code, mark a code as matched, sign a participant acknowledgment, or transition a relationship to `VERIFIED` without the two valid participant signatures required by the selected verification mode.

## Required evidence before production enablement

Remote safety-code verification remains feature-disabled until all of the following exist:

1. fixed cross-language derivation test vectors for canonical transcript -> 60-digit code
2. positive two-device test proving both devices render exactly the same code
3. negative tests for peer-key substitution, transcript mutation, stale pairing ID, expiry, and identity-key change
4. mode-confusion tests proving in-person and remote acknowledgments cannot be mixed
5. role/reflection tests proving one participant cannot satisfy both sides
6. two physical Android devices completing the intended remote-confirmation UX
7. accessibility/readability review of the full 60-digit comparison flow
8. explicit review that no safety code or acknowledgment secret is emitted to logs, analytics, notifications, or clipboard by default

## Review notes

The design follows the established safety-number principle that a human-verifiable fingerprint is useful only when compared through a second channel, and intentionally keeps the human action explicit. Signal's safety-number guidance documents visual/audible comparison and recommends a separate channel for authentication. Matrix also treats short-authentication verification as an explicit key-verification ceremony; current Matrix proposals are evolving toward secure out-of-band QR flows and away from relying on emoji SAS as the long-term UX.

References:
- https://support.signal.org/hc/en-us/articles/360007060632-What-is-a-safety-number-and-why-do-I-see-that-it-changed
- https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive
- https://spec.matrix.org/proposals/
