# ADR-001: Use Android system bubbles, never application overlays

Status: Accepted

## Decision

SecretMode uses Android Notification Bubble / system windowing for floating conversation UX and a normal Activity fallback.

SecretMode will not request or implement:

- `SYSTEM_ALERT_WINDOW`
- `TYPE_APPLICATION_OVERLAY`
- AccessibilityService for product operation
- touch interception over another application's controls

## Rationale

The system owns bubble placement and input routing. This avoids the phishing/tapjacking behavior class associated with self-managed overlays while preserving a floating conversation experience when the user and OEM permit bubbles.

## Consequences

- Bubble availability is not guaranteed.
- Users can disable notifications or bubbles.
- OEM behavior may differ.
- Store copy must not promise that floating mode is always available.
- Activity fallback is mandatory.
