//! Types used by other modules

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingKey {
    LocalStatic,
    RemoteStatic,
    LocalEphemeral,
    RemoteEphemeral,
    Psk,
}

impl fmt::Display for MissingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            MissingKey::LocalStatic => {
                "missing `.local_static_key(...)`: this pattern/role requires a local static key before `.build()`"
            }
            MissingKey::RemoteStatic => {
                "missing `.remote_static_key(...)`: the peer's static key is a pre-message for this pattern/role"
            }
            MissingKey::LocalEphemeral => {
                "missing `.local_ephemeral_key(...)`: this role sends a message and needs its own ephemeral key"
            }
            MissingKey::RemoteEphemeral => {
                "missing `.remote_ephemeral_key(...)`: the peer's ephemeral key is a pre-message for this pattern/role"
            }
            MissingKey::Psk => "missing `.psk(...)`: the pattern requires a psk to be valid",
        };
        f.write_str(msg)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseError {
    MissingRequirements(MissingKey),
    ConversionError(&'static str),
    HandshakeFinished,
    InvalidInput(&'static str),
    InvalidState(&'static str),
    Unsupported(&'static str),
    MaxNValue,
    Rekey(&'static str),
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoiseError::MissingRequirements(k) => write!(f, "cannot build: {k}"),
            NoiseError::ConversionError(msg) => write!(f, "conversion error: {msg}"),
            NoiseError::HandshakeFinished => write!(f, "handshake already finished"),
            NoiseError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            NoiseError::InvalidState(msg) => write!(f, "invalid state: {msg}"),
            NoiseError::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            NoiseError::MaxNValue => f.write_str("nonce counter reached its maximum value"),
            NoiseError::Rekey(msg) => write!(f, "rekey failed: {msg}"),
        }
    }
}

impl core::error::Error for NoiseError {}
