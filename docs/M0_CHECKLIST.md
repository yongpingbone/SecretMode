# M0 Foundation / Crypto Spike Checklist

## Repository safety
- [x] Separate repository
- [x] Neutral product identity
- [x] No third-party app name/logo dependency
- [x] No AccessibilityService
- [x] No SYSTEM_ALERT_WINDOW

## Android foundation
- [x] minSdk 30
- [x] BubbleActivity is embedded + resizable
- [x] Activity fallback exists
- [x] FLAG_SECURE on private surface
- [x] Sensitive Views opt out of hierarchy state save
- [x] Autofill/content capture disabled on private input
- [x] API 35+ content sensitivity marker
- [x] Draft/rendered private UI cleared on stop/destroy
- [ ] Real-device Bubble test on at least two OEMs

## Crypto spike
- [x] vodozemac pinned to 0.10.0
- [x] host A/B Olm roundtrip test exists
- [x] JNI boundary exists
- [ ] Android arm64-v8a native build
- [ ] JNI probe invoked from Android test-only path
- [ ] 1,000 bidirectional message test
- [ ] dropped/out-of-order test
- [ ] replay test
- [ ] pickle/restore across process death
- [ ] destroyed state cannot decrypt old session
- [ ] authenticated pairing design accepted
- [ ] third-party license review

## Protocol
- [x] encrypted envelope schema exists
- [x] ratchet header opaque to backend
- [ ] anti-replay/session event schema
- [ ] revoke event schema
- [ ] signed lease schema

## Gate
M0 must not be merged as a production-ready E2EE implementation. Passing this checklist only authorizes work on M1 pairing.
