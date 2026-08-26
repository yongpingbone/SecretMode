#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    Issued,
    Accepted,
    Confirmed,
    Verified,
    Expired,
    Cancelled,
    KeyChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    PairingIdMismatch,
    TranscriptDigestMismatch,
    InviteExpired,
    InvalidTransition {
        from: PairingState,
        action: &'static str,
    },
}

#[derive(Debug, Clone)]
pub struct PairingStateMachine {
    pairing_id: [u8; 16],
    transcript_digest: [u8; 32],
    expires_at_ms: u64,
    state: PairingState,
}

impl PairingStateMachine {
    pub fn new(pairing_id: [u8; 16], transcript_digest: [u8; 32], expires_at_ms: u64) -> Self {
        Self {
            pairing_id,
            transcript_digest,
            expires_at_ms,
            state: PairingState::Issued,
        }
    }

    pub fn state(&self) -> PairingState {
        self.state
    }

    pub fn accept(
        &mut self,
        pairing_id: &[u8; 16],
        transcript_digest: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), PairingError> {
        self.require_binding(pairing_id, transcript_digest)?;
        self.require_unexpired(now_ms)?;
        self.transition(PairingState::Issued, PairingState::Accepted, "accept")
    }

    pub fn confirm(
        &mut self,
        pairing_id: &[u8; 16],
        transcript_digest: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), PairingError> {
        self.require_binding(pairing_id, transcript_digest)?;
        self.require_unexpired(now_ms)?;
        self.transition(PairingState::Accepted, PairingState::Confirmed, "confirm")
    }

    pub fn verify_human(
        &mut self,
        pairing_id: &[u8; 16],
        transcript_digest: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), PairingError> {
        self.require_binding(pairing_id, transcript_digest)?;
        self.require_unexpired(now_ms)?;
        self.transition(PairingState::Confirmed, PairingState::Verified, "verify_human")
    }

    pub fn expire(&mut self, now_ms: u64) -> Result<(), PairingError> {
        if now_ms < self.expires_at_ms {
            return Err(PairingError::InvalidTransition {
                from: self.state,
                action: "expire_before_deadline",
            });
        }
        match self.state {
            PairingState::Issued | PairingState::Accepted | PairingState::Confirmed => {
                self.state = PairingState::Expired;
                Ok(())
            }
            from => Err(PairingError::InvalidTransition {
                from,
                action: "expire",
            }),
        }
    }

    pub fn cancel(&mut self) -> Result<(), PairingError> {
        match self.state {
            PairingState::Issued | PairingState::Accepted | PairingState::Confirmed => {
                self.state = PairingState::Cancelled;
                Ok(())
            }
            from => Err(PairingError::InvalidTransition {
                from,
                action: "cancel",
            }),
        }
    }

    pub fn mark_key_changed(&mut self) -> Result<(), PairingError> {
        match self.state {
            PairingState::Issued
            | PairingState::Accepted
            | PairingState::Confirmed
            | PairingState::Verified => {
                self.state = PairingState::KeyChanged;
                Ok(())
            }
            from => Err(PairingError::InvalidTransition {
                from,
                action: "mark_key_changed",
            }),
        }
    }

    fn require_binding(
        &self,
        pairing_id: &[u8; 16],
        transcript_digest: &[u8; 32],
    ) -> Result<(), PairingError> {
        if pairing_id != &self.pairing_id {
            return Err(PairingError::PairingIdMismatch);
        }
        if transcript_digest != &self.transcript_digest {
            return Err(PairingError::TranscriptDigestMismatch);
        }
        Ok(())
    }

    fn require_unexpired(&self, now_ms: u64) -> Result<(), PairingError> {
        if now_ms >= self.expires_at_ms {
            return Err(PairingError::InviteExpired);
        }
        Ok(())
    }

    fn transition(
        &mut self,
        expected: PairingState,
        next: PairingState,
        action: &'static str,
    ) -> Result<(), PairingError> {
        if self.state != expected {
            return Err(PairingError::InvalidTransition {
                from: self.state,
                action,
            });
        }
        self.state = next;
        Ok(())
    }
}
