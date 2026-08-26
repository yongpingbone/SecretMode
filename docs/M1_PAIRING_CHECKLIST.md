# M1 Authenticated Pairing Checklist

## Device identity
- [ ] AndroidKeyStore P-256 signing key probe passes on emulator
- [ ] identity public key is stable across reopen
- [ ] tampered payload fails identity signature verification
- [ ] real-device security level recorded without overclaiming StrongBox

## Transcript
- [ ] canonical transcript encoding locked
- [ ] inviter and invitee signatures bind the same transcript
- [ ] peer/key substitution fails verification
- [ ] role-reflection signature reuse fails verification
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
