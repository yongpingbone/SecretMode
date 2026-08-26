# M1 Authenticated Pairing Checklist

## Device identity
- [x] AndroidKeyStore P-256 signing key probe passes on emulator
- [x] identity public key is stable across reopen
- [x] tampered payload fails identity signature verification
- [ ] real-device security level recorded without overclaiming StrongBox

## Transcript
- [x] canonical transcript encoding locked
- [x] inviter and invitee signatures bind the same transcript
- [x] peer/key substitution fails verification
- [x] role-reflection signature reuse fails verification
- [ ] invite expiry and one-time consumption model tested

## Human verification
- [ ] final QR verification UX accepted
- [ ] remote safety-code design reviewed before enablement
- [ ] relationship cannot become VERIFIED without explicit verification
- [ ] device key change forces re-verification

## Service boundary
- [ ] participant-authorized revoke request signature flow defined
- [ ] authoritative state/lease signer trust and rotation design accepted
- [ ] relay is not an implicit signing authority

## Gate
Do not mark `authenticated pairing design accepted` in M0 until the full pairing handshake, human verification, replay/expiry behavior, and key-change behavior have evidence.
