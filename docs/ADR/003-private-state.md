# ADR-003: Private plaintext never participates in Android state restoration

Status: Accepted

## Rule

Private plaintext MUST NOT participate in Android state restoration.

## Android Views

Sensitive views must disable hierarchy state saving:

- `isSaveEnabled = false`
- `isSaveFromParentEnabled = false`

Private inputs must also opt out of autofill and content capture.

## Activities

Private activities must not place drafts, decoded messages, attachment names, keys, or session plaintext in `Bundle` state. Process-death recovery must reconstruct from encrypted state after validating session/lease status.

## Compose

If Compose is introduced later, private plaintext must not use:

- `rememberSaveable`
- `SavedStateHandle`

Use in-memory state only and rebuild from encrypted authoritative state after process death.

## Additional controls

- `FLAG_SECURE` on private surfaces
- API 35+ content sensitivity marking
- clear rendered plaintext and drafts when leaving the private surface
- no private text in notification previews
