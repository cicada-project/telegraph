//! T0-owned client façade declarations.
//!
//! T3/T5 add state, transport, channel, and bridge implementations beneath
//! their owned subdirectories. These declarations deliberately contain no
//! network, crypto, Codex, or persistence behavior.

#![forbid(unsafe_code)]

// Pre-handoff inline modules keep this T0-owned root compilable while the
// implementation directories remain absent. T0 replaces these with external
// module declarations only when their owning task is handed off.
pub mod bridge {}
pub mod channel {}
pub mod state {}
pub mod transport {}

/// Stable client-to-relay transport façade reserved for T3.
pub trait RelayTransport: Send + Sync {
    /// The implementation's bounded, typed error.
    type Error: Send + Sync + 'static;
}

/// Stable local Codex companion façade reserved for T5.
pub trait CodexEndpoint: Send + Sync {
    /// The implementation's bounded, typed error.
    type Error: Send + Sync + 'static;
}
