use thiserror::Error;

use crate::handoff::HandoffError;

#[derive(Debug, Error)]
pub enum MigrateError {
    #[error("{0}")]
    Usage(String),

    #[error("manifest: {0}")]
    Manifest(String),

    #[error("transport: {0}")]
    Transport(String),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("capsule: {0}")]
    Capsule(#[from] zns_canon::capsule::CapsuleError),

    #[error("tee: {0}")]
    Tee(#[from] zns_canon::sealing::TeeError),

    #[error("handoff: {0}")]
    Handoff(#[from] HandoffError),

    #[error("target measurement is not authorized")]
    Measurement,

    #[error("source measurement is not authorized")]
    SourceMeasurement,

    #[error("attestation measurement is all zeros")]
    ZeroMeasurement,

    #[error("target guest policy is not authorized")]
    GuestPolicy,

    #[error("source guest policy is not authorized")]
    SourceGuestPolicy,

    #[error("attestation guest policy is zero")]
    ZeroGuestPolicy,

    #[error("capsule fingerprint is not the authorized seed")]
    SeedFingerprint,

    #[error("capsule file is not the authorized source capsule")]
    SourceCapsule,

    #[error("migration offer is for a different manifest")]
    ManifestHash,

    #[error("upgrade: {0}")]
    Upgrade(#[from] zns_canon::upgrade::UpgradeError),
}

impl MigrateError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    pub fn manifest(message: impl Into<String>) -> Self {
        Self::Manifest(message.into())
    }

    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport(message.into())
    }

    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub fn is_usage(&self) -> bool {
        matches!(self, Self::Usage(_))
    }
}
