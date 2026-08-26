#[path = "../src/pairing.rs"]
mod pairing;

use pairing::{PairingError, PairingState, PairingStateMachine};

const PAIRING_ID: [u8; 16] = [0x11; 16];
const DIGEST: [u8; 32] = [0x22; 32];
const EXPIRES_AT: u64 = 10_000;

fn machine() -> PairingStateMachine {
    PairingStateMachine::new(PAIRING_ID, DIGEST, EXPIRES_AT)
}

#[test]
fn full_flow_requires_explicit_human_verification() {
    let mut state = machine();
    state.accept(&PAIRING_ID, &DIGEST, 1_000).unwrap();
    state.confirm(&PAIRING_ID, &DIGEST, 2_000).unwrap();
    assert_eq!(state.state(), PairingState::Confirmed);
    assert_ne!(state.state(), PairingState::Verified);
    state.verify_human(&PAIRING_ID, &DIGEST, 3_000).unwrap();
    assert_eq!(state.state(), PairingState::Verified);
}

#[test]
fn verified_cannot_be_reached_out_of_order() {
    let mut state = machine();
    assert!(matches!(
        state.verify_human(&PAIRING_ID, &DIGEST, 1_000),
        Err(PairingError::InvalidTransition { .. })
    ));
    state.accept(&PAIRING_ID, &DIGEST, 2_000).unwrap();
    assert!(matches!(
        state.verify_human(&PAIRING_ID, &DIGEST, 3_000),
        Err(PairingError::InvalidTransition { .. })
    ));
    assert_eq!(state.state(), PairingState::Accepted);
}

#[test]
fn pairing_id_and_digest_are_bound() {
    let mut state = machine();
    let wrong_id = [0x33; 16];
    let wrong_digest = [0x44; 32];
    assert_eq!(
        state.accept(&wrong_id, &DIGEST, 1_000),
        Err(PairingError::PairingIdMismatch)
    );
    assert_eq!(
        state.accept(&PAIRING_ID, &wrong_digest, 1_000),
        Err(PairingError::TranscriptDigestMismatch)
    );
    assert_eq!(state.state(), PairingState::Issued);
}

#[test]
fn duplicate_accept_is_rejected() {
    let mut state = machine();
    state.accept(&PAIRING_ID, &DIGEST, 1_000).unwrap();
    assert!(matches!(
        state.accept(&PAIRING_ID, &DIGEST, 1_500),
        Err(PairingError::InvalidTransition {
            from: PairingState::Accepted,
            ..
        })
    ));
}

#[test]
fn expired_invite_cannot_progress() {
    let mut state = machine();
    assert_eq!(
        state.accept(&PAIRING_ID, &DIGEST, EXPIRES_AT),
        Err(PairingError::InviteExpired)
    );
    state.expire(EXPIRES_AT).unwrap();
    assert_eq!(state.state(), PairingState::Expired);
    assert!(matches!(
        state.accept(&PAIRING_ID, &DIGEST, EXPIRES_AT + 1),
        Err(PairingError::InviteExpired)
            | Err(PairingError::InvalidTransition { .. })
    ));
}

#[test]
fn cancel_is_terminal_for_handshake() {
    let mut state = machine();
    state.cancel().unwrap();
    assert_eq!(state.state(), PairingState::Cancelled);
    assert!(matches!(
        state.accept(&PAIRING_ID, &DIGEST, 1_000),
        Err(PairingError::InvalidTransition { .. })
    ));
}

#[test]
fn key_change_invalidates_verified_relationship() {
    let mut state = machine();
    state.accept(&PAIRING_ID, &DIGEST, 1_000).unwrap();
    state.confirm(&PAIRING_ID, &DIGEST, 2_000).unwrap();
    state.verify_human(&PAIRING_ID, &DIGEST, 3_000).unwrap();
    state.mark_key_changed().unwrap();
    assert_eq!(state.state(), PairingState::KeyChanged);
    assert!(matches!(
        state.verify_human(&PAIRING_ID, &DIGEST, 4_000),
        Err(PairingError::InvalidTransition { .. })
    ));
}

#[test]
fn schemas_are_valid_json() {
    for schema in [
        include_str!("../../protocol/pairing-invite.schema.json"),
        include_str!("../../protocol/pairing-accept.schema.json"),
        include_str!("../../protocol/pairing-confirm.schema.json"),
    ] {
        let parsed: serde_json::Value = serde_json::from_str(schema).unwrap();
        assert_eq!(parsed["$schema"], "https://json-schema.org/draft/2020-12/schema");
        assert_eq!(parsed["additionalProperties"], false);
    }
}
