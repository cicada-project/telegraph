//! T0 migration namespace handoff.
//!
//! T2 and T3 own separate migration trees. This file only names the two
//! namespaces and records their ownership; it must not open a database or
//! execute schema/product behavior.

/// Namespace owned by T2 for relay-opaque rows only.
pub const RELAY_OPAQUE_NAMESPACE: &str = "relay_opaque";

/// Namespace owned by T3 for client-secret rows only.
pub const CLIENT_SECRET_NAMESPACE: &str = "client_secret";

/// The migration streams that T0 will integrate after their owner handoffs.
pub const OWNED_NAMESPACES: [&str; 2] = [RELAY_OPAQUE_NAMESPACE, CLIENT_SECRET_NAMESPACE];
