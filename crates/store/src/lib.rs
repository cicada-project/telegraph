//! T0-owned store boundary declarations.
//!
//! The relay-opaque and client-secret implementations are intentionally
//! absent from the T0 scaffold. T2 and T3 add code only below their owned
//! subdirectories and implement these narrow extension points without
//! exchanging types across the trust boundary.

#![forbid(unsafe_code)]

pub mod migrations;

// Pre-handoff inline modules keep this T0-owned root compilable while the
// implementation directories remain absent. T0 replaces each with an
// external module declaration only when its owning task is handed off.
pub mod client_secret {}
pub mod relay_opaque {}

/// Stable server-side persistence façade reserved for T2.
///
/// T0 intentionally keeps this façade behavior-free: operation request and
/// result types belong to the relay-opaque store task and are not invented in
/// the neutral scaffold.
pub trait MailboxStore: Send + Sync {
    /// The implementation's bounded, typed error.
    type Error: Send + Sync + 'static;
}

/// Stable local secret-state façade reserved for T3.
///
/// No private material, plaintext, provider type, or persistence operation is
/// represented by this marker in T0.
pub trait ClientSecretStore: Send + Sync {
    /// The implementation's fail-closed, typed error.
    type Error: Send + Sync + 'static;
}
