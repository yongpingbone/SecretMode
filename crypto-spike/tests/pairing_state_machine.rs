#[path = "../src/pairing.rs"]
mod pairing;

use pairing::{PairingError, PairingRole, PairingState, PairingStateMachine};

const PAIRING_ID: [u8; 16] = [0x11; 16];
const DIGEST: [u8; 32] = [0x22; 32];
const EXPIRES_AT: u64 = 10_000;

fn machine() -> PairingStateMachine {
    PairingStateMachine::new(PAIRING_ID, DIGEST, EXPIRES_AT)
}

fn confirmed_machine() -> PairingStateMachine {
    let mut state = machine();
    state.accept(&PAIRING_ID, &DIGEST, 1_000).unwrap();
    state.confirm(&PAIRING_ID, &DIGEST, 2_000).unwrap();
    state
}

#[test]
fn one_human_ack_is_never_enough_to_verify_relationship() {
    let mut state = confirmed_machine();
    assert!(!state
        .record_human_verification(PairingRole::Invitee, &PAIRING_ID, &DIGEST, 3_000)
        .unwrap());
    assert_eq!(state.state(), PairingState::Confirmed);
    assert!(!state.human_verification_complete());
}

#[test]
fn both_human_acks_are_required_for_verified() {
    let mut state = confirmed_machine();
    assert!(!state
        .record_human_verification(PairingRole::Invitee, &PAIRING_ID, &DIGEST, 3_000)
        .unwrap());
    assert!(state
        .record_human_verification(PairingRole::Inviter, &PAIRING_ID, &DIGEST, 4_000)
        .unwrap());
    assert_eq!(state.state(), PairingState::Verified);
    assert!(state.human_verification_complete());
}

#[test]
fn repeating_same_role_ack_cannot_fake_two_party_verification() {
    let mut state = confirmed_machine();
    assert!(!state
        .record_human_verification(PairingRole::Invitee, &PAIRING_ID, &DIGEST, 3_000)
        .unwrap());
    assert!(!state
        .record_human_verification(PairingRole::Invitee, &PAIRING_ID, &DIGEST, 4_000)
        .unwrap());
    assert_eq!(state.state(), PairingState::Confirmed);
}

#[test]
fn verified_cannot_be_reached_before_confirmed() {
    let mut state = machine();
    assert!(matches!(
        state.record_human_verification(PairingRole::Inviter, &PAIRING_ID, &DIGEST, 1_000),
        Err(PairingError::InvalidTransition { .. })
    ));
    state.accept(&PAIRING_ID, &DIGEST, 2_000).unwrap();
    assert!(matches!(
        state.record_human_verification(PairingRole::Invitee, &PAIRING_ID, &DIGEST, 3_000),
        Err(PairingError::InvalidTransition { .. })
    ));
}

#[test]
fn expiry_between_human_acks_blocks_completion() {
    let mut state = confirmed_machine();
    state
        .record_human_verification(PairingRole::Invitee, &PAIRING_ID, &DIGEST, 9_000)
        .unwrap();
    assert_eq!(
        state.record_human_verification(PairingRole::Inviter, &PAIRING_ID, &DIGEST, EXPIRES_AT),
        Err(PairingError::InviteExpired)
    );
    state.expire(EXPIRES_AT).unwrap();
    assert_eq!(state.state(), PairingState::Expired);
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
    let mut state = confirmed_machine();
    state
        .record_human_verification(PairingRole::Inviter, &PAIRING_ID, &DIGEST, 3_000)
        .unwrap();
    state
        .record_human_verification(PairingRole::Invitee, &PAIRING_ID, &DIGEST, 4_000)
        .unwrap();
    assert_eq!(state.state(), PairingState::Verified);
    state.mark_key_changed().unwrap();
    assert_eq!(state.state(), PairingState::KeyChanged);
    assert!(matches!(
        state.record_human_verification(PairingRole::Inviter, &PAIRING_ID, &DIGEST, 5_000),
        Err(PairingError::InvalidTransition { .. })
    ));
}

#[test]
fn schemas_are_valid_json() {
    for schema in [
        include_str!("../../protocol/pairing-invite.schema.json"),
        include_str!("../../protocol/pairing-accept.schema.json"),
        include_str!("../../protocol/pairing-confirm.schema.json"),
        include_str!("../../protocol/pairing-verification-ack.schema.json"),
    ] {
        let parsed: serde_json::Value = serde_json::from_str(schema).unwrap();
        assert_eq!(parsed["$schema"], "https://json-schema.org/draft/2020-12/schema");
        assert_eq!(parsed["additionalProperties"], false);
    }
}
