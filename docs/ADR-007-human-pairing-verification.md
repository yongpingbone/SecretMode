# ADR-007: Two-party human verification before VERIFIED

Status: M1 candidate

## Decision

Mutual device-key signatures authenticate possession of the two device identity private keys, but they do not prove that the keys belong to the two humans who intend to pair. SecretMode therefore keeps a pairing in `CONFIRMED` after cryptographic transcript confirmation and requires explicit human acknowledgments from both participants before it can become `VERIFIED`.

One acknowledgment is insufficient. Repeating the same participant's acknowledgment is also insufficient.

## In-person primary flow

The intended primary flow is asymmetric but two-party:

1. both devices complete and verify the signed final pairing transcript
2. one participant scans a final verification QR shown directly on the peer device; the QR is derived from the final transcript digest
3. the scanning device records an explicit `in_person_qr_scan` human acknowledgment bound to the pairing ID and transcript digest
4. the displaying participant explicitly confirms that the other person/device is the intended peer and records an `in_person_peer_confirm` acknowledgment
5. only after both role-bound acknowledgments are verified may the relationship transition from `CONFIRMED` to `VERIFIED`

A relayed screenshot of the QR cannot be distinguished cryptographically from a directly viewed QR. The UX must therefore state that the in-person QR is to be scanned from the peer's device screen. Remote verification requires a separately reviewed safety-code method and is not enabled by this ADR.

## Acknowledgment binding

A human-verification acknowledgment binds at minimum:

- protocol version/domain
- pairing ID
- final transcript digest
- verifier role
- verifier device ID
- verification method
- verification timestamp

The acknowledgment is signed with the verifier's already-bound device identity key. Transporting the acknowledgment through a relay does not grant the relay authority to create one.

## Expiry and key changes

Both acknowledgments must be recorded before the pairing invite expires. If expiry occurs after only one acknowledgment, the relationship cannot complete and a new pairing must start.

Any device identity key change moves the relationship to `KEY_CHANGED`. Previous human acknowledgments do not silently transfer to the new key. Re-verification must use a fresh pairing transcript.
