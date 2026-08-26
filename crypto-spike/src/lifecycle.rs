use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLifecycle {
    Creating,
    Active,
    Revoking,
    Revoked,
    Purged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEventKind {
    SessionActivated,
    RevokeRequested,
    SessionRevoked,
    SessionPurged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSessionEvent {
    pub event_id: String,
    pub session_id: String,
    pub state_version: u64,
    pub kind: SessionEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseClaims {
    pub lease_id: String,
    pub session_id: String,
    pub holder_device_id: String,
    pub state_version: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    EventSessionMismatch,
    DuplicateEvent,
    StaleStateVersion,
    InvalidTransition {
        from: SessionLifecycle,
        event: SessionEventKind,
    },
    SessionNotActive,
    InvalidLeaseLifetime,
    LeaseBindingMismatch,
    LeaseNotYetValid,
    LeaseExpired,
    StaleLeaseStateVersion,
    FutureLeaseStateVersion,
}

#[derive(Debug, Clone)]
pub struct SessionLifecycleState {
    session_id: String,
    lifecycle: SessionLifecycle,
    highest_state_version: u64,
    seen_event_ids: HashSet<String>,
}

impl SessionLifecycleState {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            lifecycle: SessionLifecycle::Creating,
            highest_state_version: 0,
            seen_event_ids: HashSet::new(),
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle
    }

    pub fn highest_state_version(&self) -> u64 {
        self.highest_state_version
    }

    pub fn apply_verified_event(
        &mut self,
        event: &VerifiedSessionEvent,
    ) -> Result<(), LifecycleError> {
        if event.session_id != self.session_id {
            return Err(LifecycleError::EventSessionMismatch);
        }
        if self.seen_event_ids.contains(&event.event_id) {
            return Err(LifecycleError::DuplicateEvent);
        }
        if event.state_version <= self.highest_state_version {
            return Err(LifecycleError::StaleStateVersion);
        }

        let next = match (self.lifecycle, event.kind) {
            (SessionLifecycle::Creating, SessionEventKind::SessionActivated) => {
                SessionLifecycle::Active
            }
            (SessionLifecycle::Active, SessionEventKind::RevokeRequested) => {
                SessionLifecycle::Revoking
            }
            (SessionLifecycle::Revoking, SessionEventKind::SessionRevoked) => {
                SessionLifecycle::Revoked
            }
            (SessionLifecycle::Revoked, SessionEventKind::SessionPurged) => {
                SessionLifecycle::Purged
            }
            (from, kind) => {
                return Err(LifecycleError::InvalidTransition { from, event: kind });
            }
        };

        self.lifecycle = next;
        self.highest_state_version = event.state_version;
        self.seen_event_ids.insert(event.event_id.clone());
        Ok(())
    }

    pub fn lease_claims_for_signing(
        &self,
        lease_id: impl Into<String>,
        holder_device_id: impl Into<String>,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<LeaseClaims, LifecycleError> {
        if self.lifecycle != SessionLifecycle::Active {
            return Err(LifecycleError::SessionNotActive);
        }
        if expires_at_ms <= issued_at_ms {
            return Err(LifecycleError::InvalidLeaseLifetime);
        }

        Ok(LeaseClaims {
            lease_id: lease_id.into(),
            session_id: self.session_id.clone(),
            holder_device_id: holder_device_id.into(),
            state_version: self.highest_state_version,
            issued_at_ms,
            expires_at_ms,
        })
    }

    pub fn validate_verified_lease(
        &self,
        lease: &LeaseClaims,
        expected_holder_device_id: &str,
        now_ms: u64,
    ) -> Result<(), LifecycleError> {
        if self.lifecycle != SessionLifecycle::Active {
            return Err(LifecycleError::SessionNotActive);
        }
        if lease.session_id != self.session_id || lease.holder_device_id != expected_holder_device_id {
            return Err(LifecycleError::LeaseBindingMismatch);
        }
        if lease.state_version < self.highest_state_version {
            return Err(LifecycleError::StaleLeaseStateVersion);
        }
        if lease.state_version > self.highest_state_version {
            return Err(LifecycleError::FutureLeaseStateVersion);
        }
        if lease.expires_at_ms <= lease.issued_at_ms {
            return Err(LifecycleError::InvalidLeaseLifetime);
        }
        if now_ms < lease.issued_at_ms {
            return Err(LifecycleError::LeaseNotYetValid);
        }
        if now_ms >= lease.expires_at_ms {
            return Err(LifecycleError::LeaseExpired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION_ID: &str = "session-000000000001";
    const DEVICE_ID: &str = "device-0000000000001";

    fn event(id: &str, version: u64, kind: SessionEventKind) -> VerifiedSessionEvent {
        VerifiedSessionEvent {
            event_id: id.to_owned(),
            session_id: SESSION_ID.to_owned(),
            state_version: version,
            kind,
        }
    }

    fn active_state() -> SessionLifecycleState {
        let mut state = SessionLifecycleState::new(SESSION_ID);
        state
            .apply_verified_event(&event(
                "evt-0000000000000001",
                1,
                SessionEventKind::SessionActivated,
            ))
            .unwrap();
        state
    }

    #[test]
    fn normal_lifecycle_reaches_revoked_then_purged() {
        let mut state = active_state();
        state
            .apply_verified_event(&event(
                "evt-0000000000000002",
                2,
                SessionEventKind::RevokeRequested,
            ))
            .unwrap();
        state
            .apply_verified_event(&event(
                "evt-0000000000000003",
                3,
                SessionEventKind::SessionRevoked,
            ))
            .unwrap();
        assert_eq!(state.lifecycle(), SessionLifecycle::Revoked);
        state
            .apply_verified_event(&event(
                "evt-0000000000000004",
                4,
                SessionEventKind::SessionPurged,
            ))
            .unwrap();
        assert_eq!(state.lifecycle(), SessionLifecycle::Purged);
        assert_eq!(state.highest_state_version(), 4);
    }

    #[test]
    fn cross_session_event_is_rejected() {
        let mut state = active_state();
        let mut wrong = event(
            "evt-0000000000000002",
            2,
            SessionEventKind::RevokeRequested,
        );
        wrong.session_id = "session-OTHER-00000001".to_owned();
        assert_eq!(
            state.apply_verified_event(&wrong),
            Err(LifecycleError::EventSessionMismatch)
        );
        assert_eq!(state.lifecycle(), SessionLifecycle::Active);
        assert_eq!(state.highest_state_version(), 1);
    }

    #[test]
    fn revoked_session_cannot_reactivate_even_with_higher_version() {
        let mut state = active_state();
        state
            .apply_verified_event(&event(
                "evt-0000000000000002",
                2,
                SessionEventKind::RevokeRequested,
            ))
            .unwrap();
        state
            .apply_verified_event(&event(
                "evt-0000000000000003",
                3,
                SessionEventKind::SessionRevoked,
            ))
            .unwrap();

        let error = state
            .apply_verified_event(&event(
                "evt-0000000000000099",
                99,
                SessionEventKind::SessionActivated,
            ))
            .unwrap_err();
        assert_eq!(
            error,
            LifecycleError::InvalidTransition {
                from: SessionLifecycle::Revoked,
                event: SessionEventKind::SessionActivated,
            }
        );
        assert_eq!(state.lifecycle(), SessionLifecycle::Revoked);
        assert_eq!(state.highest_state_version(), 3);
    }

    #[test]
    fn old_active_event_replay_cannot_resurrect_revoked_session() {
        let mut state = active_state();
        state
            .apply_verified_event(&event(
                "evt-0000000000000002",
                2,
                SessionEventKind::RevokeRequested,
            ))
            .unwrap();
        state
            .apply_verified_event(&event(
                "evt-0000000000000003",
                3,
                SessionEventKind::SessionRevoked,
            ))
            .unwrap();

        assert_eq!(
            state
                .apply_verified_event(&event(
                    "evt-old-active-replay-0001",
                    1,
                    SessionEventKind::SessionActivated,
                ))
                .unwrap_err(),
            LifecycleError::StaleStateVersion
        );
        assert_eq!(state.lifecycle(), SessionLifecycle::Revoked);
    }

    #[test]
    fn purged_session_is_terminal() {
        let mut state = active_state();
        for (id, version, kind) in [
            ("evt-0000000000000002", 2, SessionEventKind::RevokeRequested),
            ("evt-0000000000000003", 3, SessionEventKind::SessionRevoked),
            ("evt-0000000000000004", 4, SessionEventKind::SessionPurged),
        ] {
            state.apply_verified_event(&event(id, version, kind)).unwrap();
        }

        assert!(matches!(
            state.apply_verified_event(&event(
                "evt-0000000000000005",
                5,
                SessionEventKind::SessionActivated,
            )),
            Err(LifecycleError::InvalidTransition {
                from: SessionLifecycle::Purged,
                ..
            })
        ));
    }

    #[test]
    fn duplicate_event_id_is_rejected() {
        let mut state = active_state();
        assert_eq!(
            state
                .apply_verified_event(&event(
                    "evt-0000000000000001",
                    2,
                    SessionEventKind::RevokeRequested,
                ))
                .unwrap_err(),
            LifecycleError::DuplicateEvent
        );
    }

    #[test]
    fn stale_state_version_is_rejected() {
        let mut state = active_state();
        assert_eq!(
            state
                .apply_verified_event(&event(
                    "evt-0000000000000002",
                    1,
                    SessionEventKind::RevokeRequested,
                ))
                .unwrap_err(),
            LifecycleError::StaleStateVersion
        );
    }

    #[test]
    fn active_lease_is_valid_before_expiry() {
        let state = active_state();
        let lease = state
            .lease_claims_for_signing("lease-00000000000001", DEVICE_ID, 1_000, 2_000)
            .unwrap();
        assert_eq!(lease.session_id, SESSION_ID);
        assert_eq!(lease.state_version, 1);
        state.validate_verified_lease(&lease, DEVICE_ID, 1_999).unwrap();
    }

    #[test]
    fn lease_with_wrong_session_or_device_is_rejected() {
        let state = active_state();
        let mut lease = state
            .lease_claims_for_signing("lease-00000000000001", DEVICE_ID, 1_000, 2_000)
            .unwrap();
        lease.session_id = "session-OTHER-00000001".to_owned();
        assert_eq!(
            state.validate_verified_lease(&lease, DEVICE_ID, 1_500),
            Err(LifecycleError::LeaseBindingMismatch)
        );

        lease.session_id = SESSION_ID.to_owned();
        assert_eq!(
            state.validate_verified_lease(&lease, "device-OTHER-00000001", 1_500),
            Err(LifecycleError::LeaseBindingMismatch)
        );
    }

    #[test]
    fn lease_is_rejected_after_revocation_begins() {
        let mut state = active_state();
        let lease = state
            .lease_claims_for_signing("lease-00000000000001", DEVICE_ID, 1_000, 2_000)
            .unwrap();
        state
            .apply_verified_event(&event(
                "evt-0000000000000002",
                2,
                SessionEventKind::RevokeRequested,
            ))
            .unwrap();

        assert_eq!(
            state.validate_verified_lease(&lease, DEVICE_ID, 1_500),
            Err(LifecycleError::SessionNotActive)
        );
        assert_eq!(
            state.lease_claims_for_signing(
                "lease-00000000000002",
                DEVICE_ID,
                1_500,
                2_500,
            ),
            Err(LifecycleError::SessionNotActive)
        );
    }

    #[test]
    fn lease_time_bounds_are_enforced() {
        let state = active_state();
        let lease = state
            .lease_claims_for_signing("lease-00000000000001", DEVICE_ID, 1_000, 2_000)
            .unwrap();

        assert_eq!(
            state.validate_verified_lease(&lease, DEVICE_ID, 999),
            Err(LifecycleError::LeaseNotYetValid)
        );
        assert_eq!(
            state.validate_verified_lease(&lease, DEVICE_ID, 2_000),
            Err(LifecycleError::LeaseExpired)
        );

        let mut malformed = lease.clone();
        malformed.expires_at_ms = malformed.issued_at_ms;
        assert_eq!(
            state.validate_verified_lease(&malformed, DEVICE_ID, 1_000),
            Err(LifecycleError::InvalidLeaseLifetime)
        );
    }

    #[test]
    fn stale_and_future_lease_versions_are_rejected() {
        let state = active_state();
        let mut lease = state
            .lease_claims_for_signing("lease-00000000000001", DEVICE_ID, 1_000, 2_000)
            .unwrap();

        lease.state_version = 0;
        assert_eq!(
            state.validate_verified_lease(&lease, DEVICE_ID, 1_500),
            Err(LifecycleError::StaleLeaseStateVersion)
        );

        lease.state_version = 2;
        assert_eq!(
            state.validate_verified_lease(&lease, DEVICE_ID, 1_500),
            Err(LifecycleError::FutureLeaseStateVersion)
        );
    }

    #[test]
    fn protocol_schemas_are_valid_json() {
        for schema in [
            include_str!("../../protocol/session-event.schema.json"),
            include_str!("../../protocol/revoke-event.schema.json"),
            include_str!("../../protocol/signed-lease.schema.json"),
        ] {
            let parsed: serde_json::Value = serde_json::from_str(schema).unwrap();
            assert_eq!(parsed["type"], "object");
            assert_eq!(parsed["additionalProperties"], false);
        }
    }
}
