# Threat Model

## Security goal

For normal, uncompromised SecretMode clients, a participant can end a private session so that the application will no longer render or recover that session's previous private content. Backend compromise must not reveal message plaintext.

## Non-goals / honest limits

SecretMode cannot prevent or reverse:

- a second camera photographing the screen
- a peer manually copying or memorizing content
- a rooted or OS-compromised device
- a malicious keyboard/IME capturing typed text
- a maliciously modified SecretMode build that intentionally exports plaintext
- forensic guarantees that every flash cell is synchronously overwritten

## Required invariants

1. Private plaintext is never sent through a third-party messaging service.
2. Backend never receives private plaintext or session private keys.
3. Push notifications contain opaque events only.
4. Private plaintext is excluded from logs, crash breadcrumbs, analytics, SavedState, autofill, and content capture.
5. Revocation is idempotent and authoritative on the server.
6. A revoked session can never become active again.
7. Old/replayed envelopes cannot resurrect a revoked session.
8. Session rendering requires valid local state and, when the lease model is active, a non-expired authoritative lease.
9. Device identity changes must be surfaced and require re-verification.
10. Key destruction means destruction of decryptability; deletion of rows alone is insufficient.

## Android-specific paths

### Saved state

Sensitive Views must set `isSaveEnabled=false` and `isSaveFromParentEnabled=false`. Private Activities must not restore plaintext from `Bundle`; BubbleActivity currently passes `null` to the platform state restoration path and clears any generated state bundle.

If Compose is introduced later, private plaintext MUST NOT use `rememberSaveable` or SavedStateHandle.

### Screenshots and projection

Private surfaces use `FLAG_SECURE`. API 35+ sensitive roots should also use `CONTENT_SENSITIVITY_SENSITIVE`. These controls reduce screenshot/media-projection exposure but do not protect against a compromised OS or another physical camera.

### Bubbles

Bubbles are user/OEM controlled. The app must function when bubbles are disabled. SecretMode must not add `SYSTEM_ALERT_WINDOW` as a fallback.

## Offline revoke

Remote code cannot delete data from a completely offline peer device. The intended model is:

- server immediately marks session REVOKED
- online clients purge promptly
- offline clients lose ability to obtain renewed leases after expiry
- reconnect synchronizes authoritative REVOKED state and purges local decryptability

The exact lease TTL is not fixed in M0 and must be tested against Android background/network behavior before product claims are written.
