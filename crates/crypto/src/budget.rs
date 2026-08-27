/// Olm v1's finite eight-byte authentication tag requires an application
/// policy budget. This module is a pure state machine: persistence and the
/// atomic update around a failed decrypt belong to T3b.
pub const INVALID_AUTH_ATTEMPT_LIMIT: u8 = 8;
pub const INVALID_AUTH_WINDOW_SECONDS: u64 = 600;
pub const INVALID_AUTH_STATE_BYTES: usize = 16;

const STATE_MAGIC: &[u8; 4] = b"T3AB";
const STATE_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthBudgetDecision {
    Accepted,
    InvalidAuth { attempts: u8 },
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    InvalidLength,
    InvalidEncoding,
    InvalidState,
}

/// Persistent representation for the invalid-auth budget. The binary
/// representation is fixed-size and strict; it is not a serde-facing format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidAuthBudget {
    attempts: u8,
    window_started_at: Option<u64>,
    quarantined: bool,
}

impl Default for InvalidAuthBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl InvalidAuthBudget {
    pub const fn new() -> Self {
        Self { attempts: 0, window_started_at: None, quarantined: false }
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub const fn window_started_at(&self) -> Option<u64> {
        self.window_started_at
    }

    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }

    /// Record one failed authenticated decrypt at a caller-supplied trusted
    /// timestamp. Clock rollback and arithmetic overflow are fail-closed.
    pub fn record_invalid_auth(&mut self, now_seconds: u64) -> AuthBudgetDecision {
        if self.quarantined {
            return AuthBudgetDecision::Quarantined;
        }
        match self.window_started_at {
            None => self.window_started_at = Some(now_seconds),
            Some(start) if now_seconds < start => {
                self.quarantined = true;
                return AuthBudgetDecision::Quarantined;
            }
            Some(start) if now_seconds - start >= INVALID_AUTH_WINDOW_SECONDS => {
                self.attempts = 0;
                self.window_started_at = Some(now_seconds);
            }
            Some(_) => {}
        }

        let Some(next) = self.attempts.checked_add(1) else {
            self.quarantined = true;
            return AuthBudgetDecision::Quarantined;
        };
        self.attempts = next;
        if self.attempts >= INVALID_AUTH_ATTEMPT_LIMIT {
            self.quarantined = true;
            AuthBudgetDecision::Quarantined
        } else {
            AuthBudgetDecision::InvalidAuth { attempts: self.attempts }
        }
    }

    /// A valid authenticated message clears a healthy window. It can never
    /// clear quarantine, which requires explicit repair/re-pair policy.
    pub fn record_valid_auth(&mut self, now_seconds: u64) -> AuthBudgetDecision {
        if self.quarantined {
            return AuthBudgetDecision::Quarantined;
        }
        if self.window_started_at.is_some_and(|start| now_seconds < start) {
            self.quarantined = true;
            return AuthBudgetDecision::Quarantined;
        }
        self.attempts = 0;
        self.window_started_at = None;
        AuthBudgetDecision::Accepted
    }

    pub fn quarantine(&mut self) {
        self.quarantined = true;
    }

    pub const fn repaired() -> Self {
        Self::new()
    }

    /// Encode the strict 16-byte persistent representation.
    pub fn encode(&self) -> [u8; INVALID_AUTH_STATE_BYTES] {
        let mut out = [0u8; INVALID_AUTH_STATE_BYTES];
        out[..4].copy_from_slice(STATE_MAGIC);
        out[4] = STATE_VERSION;
        out[5] = self.attempts;
        out[6] = u8::from(self.window_started_at.is_some());
        out[7..15].copy_from_slice(&self.window_started_at.unwrap_or_default().to_be_bytes());
        out[15] = u8::from(self.quarantined);
        out
    }

    /// Decode only canonical states; malformed or impossible states are
    /// rejected before they can affect a caller's budget.
    pub fn decode(bytes: &[u8]) -> Result<Self, BudgetError> {
        if bytes.len() != INVALID_AUTH_STATE_BYTES {
            return Err(BudgetError::InvalidLength);
        }
        if &bytes[..4] != STATE_MAGIC || bytes[4] != STATE_VERSION {
            return Err(BudgetError::InvalidEncoding);
        }
        let attempts = bytes[5];
        if attempts > INVALID_AUTH_ATTEMPT_LIMIT || bytes[6] > 1 || bytes[15] > 1 {
            return Err(BudgetError::InvalidState);
        }
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&bytes[7..15]);
        let window_started_at = (bytes[6] == 1).then_some(u64::from_be_bytes(timestamp));
        let quarantined = bytes[15] == 1;
        if attempts == 0 && window_started_at.is_some() {
            return Err(BudgetError::InvalidState);
        }
        if attempts > 0 && window_started_at.is_none() {
            return Err(BudgetError::InvalidState);
        }
        if attempts == INVALID_AUTH_ATTEMPT_LIMIT && !quarantined {
            return Err(BudgetError::InvalidState);
        }
        Ok(Self { attempts, window_started_at, quarantined })
    }
}
