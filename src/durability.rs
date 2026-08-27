use std::time::Duration;

/// The acknowledgement boundary for mutating operations.
///
/// Storage layout controls where live data is placed. Durability controls what
/// a successful write promises. Keeping them independent lets an in-memory
/// data set use a write-ahead log without enabling cold storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityPolicy {
    /// No automatic recovery guarantee. State may be lost when the process exits.
    Ephemeral,
    /// Append before mutation and synchronize within the configured interval.
    EverySecond,
    /// Append and synchronize before applying each mutation.
    AlwaysSync,
}

impl DurabilityPolicy {
    /// Stable lowercase name used by configuration and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::EverySecond => "every_second",
            Self::AlwaysSync => "always_sync",
        }
    }

    pub(crate) fn is_persistent(self) -> bool {
        !matches!(self, Self::Ephemeral)
    }

    pub(crate) fn syncs_each_append(self) -> bool {
        matches!(self, Self::AlwaysSync)
    }
}

/// Durability-specific runtime configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurabilityConfig {
    /// Write acknowledgement policy.
    pub policy: DurabilityPolicy,
    /// Maximum periodic WAL sync interval for `every_second`.
    pub sync_interval: Duration,
}

impl Default for DurabilityConfig {
    fn default() -> Self {
        // ServerConfig has historically been persistent by default. Preserve
        // that contract while adding a WAL to the memory layout.
        Self {
            policy: DurabilityPolicy::EverySecond,
            sync_interval: Duration::from_secs(1),
        }
    }
}
