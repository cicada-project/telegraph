//! T0-owned CLI root and module declaration handoff.
//!
//! Pairing UX and bridge supervision are owned by later tasks. The root stays
//! an inert entry point until the CLI manifest and owned modules are handed to
//! the T0 integration owner.

#![forbid(unsafe_code)]

// Pre-handoff inline modules keep this T0-owned root compilable while the
// implementation directories remain absent. T0 replaces these with external
// module declarations only when their owning task is handed off.
mod codex_bridge {}
mod pairing {}

fn main() {
    // Keep the pre-handoff binary behavior-free. A CLI flow is added only by
    // the owned task after its manifest handoff.
}
