pub const REPLAY_WINDOW_SIZE: u64 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayReject {
    Duplicate,
    TooOld,
}

/// Sliding replay window for exactly one authenticated (session, sender-device) stream.
///
/// Callers MUST feed only the sequence number recovered from authenticated Olm plaintext.
/// Outer transport-envelope sequence numbers are untrusted routing hints and must never
/// advance this state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: u128,
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            highest: None,
            seen: 0,
        }
    }

    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }

    pub fn observe(&mut self, sequence: u64) -> Result<(), ReplayReject> {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.seen = 1;
            return Ok(());
        };

        if sequence > highest {
            let advance = sequence - highest;
            self.seen = if advance >= REPLAY_WINDOW_SIZE {
                1
            } else {
                (self.seen << (advance as u32)) | 1
            };
            self.highest = Some(sequence);
            return Ok(());
        }

        let distance = highest - sequence;
        if distance >= REPLAY_WINDOW_SIZE {
            return Err(ReplayReject::TooOld);
        }

        let mask = 1u128 << (distance as u32);
        if self.seen & mask != 0 {
            return Err(ReplayReject::Duplicate);
        }

        self.seen |= mask;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplayReject, ReplayWindow};

    #[test]
    fn accepts_forward_and_out_of_order_messages_inside_window() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.observe(100), Ok(()));
        assert_eq!(window.observe(103), Ok(()));
        assert_eq!(window.observe(101), Ok(()));
        assert_eq!(window.observe(102), Ok(()));
        assert_eq!(window.highest(), Some(103));
    }

    #[test]
    fn rejects_duplicate_sequence() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.observe(42), Ok(()));
        assert_eq!(window.observe(45), Ok(()));
        assert_eq!(window.observe(42), Err(ReplayReject::Duplicate));
        assert_eq!(window.observe(45), Err(ReplayReject::Duplicate));
    }

    #[test]
    fn rejects_messages_outside_window() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.observe(1_000), Ok(()));
        assert_eq!(window.observe(873), Ok(()));
        assert_eq!(window.observe(872), Err(ReplayReject::TooOld));
    }

    #[test]
    fn large_forward_jump_forgets_only_the_expired_window() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.observe(1), Ok(()));
        assert_eq!(window.observe(500), Ok(()));
        assert_eq!(window.observe(499), Ok(()));
        assert_eq!(window.observe(1), Err(ReplayReject::TooOld));
        assert_eq!(window.observe(500), Err(ReplayReject::Duplicate));
    }
}
