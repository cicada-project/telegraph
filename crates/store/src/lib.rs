//! T0-owned store boundary declarations.
//!
//! The relay-opaque implementation is handed off below its owned module.
//! Client-secret persistence remains a T3b placeholder and exposes no
//! private material or behavior at this boundary.

#![forbid(unsafe_code)]

pub mod migrations;

// The client-secret marker remains behavior-free until the separate T3b
// journal/secure-storage handoff. The relay-opaque module is now an owned,
// reviewed implementation and is wired externally without changing its API.
pub mod client_secret {}
pub mod relay_opaque;

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
