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
- [x] Cloud backup / Android 12+ device transfer explicitly excluded
- [ ] Real-device Bubble test on at least two OEMs

## Crypto spike
- [x] vodozemac pinned to 0.10.0
- [x] host A/B Olm roundtrip test exists
- [x] JNI boundary exists
- [x] Android arm64-v8a native build
- [x] ARM64 JNI library packaged and verified inside APK
- [x] JNI probe invoked from Android test-only path
- [x] 1,000 bidirectional message test
- [x] dropped/out-of-order test
- [x] replay test with authenticated inner sequence and 128-slot window
- [x] pickle/restore across simulated process death via serialized bytes
- [x] Android Keystore cryptographic-erasure emulator probe
- [x] destroyed state cannot decrypt old real Olm SessionPickle
- [ ] authenticated pairing design accepted
- [ ] final third-party notices / legal review

## Supply chain
- [x] Rust CI toolchain pinned to 1.98.0
- [x] direct Rust dependency versions exact-pinned
- [x] GitHub Actions in M0 workflow pinned to reviewed commit SHAs
- [x] Cargo.lock committed
- [x] all M0 Cargo build/test commands use --locked
- [x] resolved Rust dependency license metadata technically screened
- [ ] release third-party notice bundle reviewed

## Protocol
- [x] encrypted envelope schema exists
- [x] ratchet header opaque to backend
- [x] authenticated inner message metadata schema exists
- [x] anti-replay/session event schema
- [x] revoke event schema
- [x] signed lease schema

## Gate
M0 must not be merged as a production-ready E2EE implementation. Passing this checklist only authorizes work on M1 pairing.
