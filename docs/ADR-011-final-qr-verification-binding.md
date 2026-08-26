# ADR-011: Final verification QR binding and two-party acknowledgment gate

Status: M1 candidate implementation

## Decision

The final in-person QR is a compact encoding of the already-finalized pairing identity, not a new trust anchor and not a bearer credential. Its v1 payload is:

`SMV1.<pairingIdB64u>.<transcriptDigestB64u>`

where `pairingId` is exactly 16 bytes and `transcriptDigest` is exactly the 32-byte SHA-256 digest of the canonical final pairing transcript. Both fields use unpadded canonical base64url. Parsers reject unknown versions, wrong field counts, wrong decoded lengths, non-canonical base64url, and surrounding whitespace.

The QR contains no private key, session key, access token, or message plaintext.

## Human acknowledgment

Scanning a matching QR does not directly change a relationship to `VERIFIED`. It creates one signed human-verification acknowledgment with method `in_person_qr_scan`. The peer who is displaying the final QR must separately confirm that the scanning person/device is the intended peer and create a signed acknowledgment with method `in_person_peer_confirm`.

Each acknowledgment is signed by the verifier's already-bound Android device identity key and binds:

- protocol/domain version
- pairing ID
- final transcript digest
- verifier role
- verifier device ID
- verification method
- verification timestamp

A valid signature from the wrong participant key, a valid signature over another transcript, a timestamp at/after pairing expiry, or a modified acknowledgment is rejected.

## VERIFIED transition

The relationship may transition from `CONFIRMED` to `VERIFIED` only when both acknowledgments verify against the same final transcript and the two acknowledgments are from opposite participant roles with opposite verification methods.

One acknowledgment is insufficient. Two acknowledgments from the same participant are insufficient. Replaying acknowledgments from an old transcript after a device identity key change is insufficient because the transcript digest and expected identity key both change.

Once both acknowledgments were validly created before pairing expiry, later relationship use does not require the wall clock to remain inside the invite window. The expiry rule constrains when human verification may be completed, not the lifetime of an already verified relationship.

## Screenshot limitation

The QR is intentionally not treated as proof of physical proximity. A relayed screenshot can carry the same public transcript binding. The user-facing flow must therefore tell users to scan the code directly from the intended peer's device screen. Remote verification is a separate method and remains disabled until its safety-code design and UX are independently reviewed.

## Implementation evidence target

Android emulator evidence must exercise canonical QR round-trip, QR tamper mismatch, single-ack rejection, same-participant double-ack rejection, two-party success, signed-field tamper rejection, expiry rejection, wrong-key rejection, and device-key-change invalidation before the human-verification core receives checklist credit.

This ADR does not by itself mark the final QR *visual/scanner UX* accepted. Rendering/scanning integration remains a separate UI gate.
