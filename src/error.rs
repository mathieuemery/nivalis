//! Types used by other modules

use core::fmt;

/// Used when a key that is required by the pattern
/// wasn't provided to the builder.
/// 
/// Also depends on the role of the of the caller
/// (initiator or responder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingKey {
    /// The local static key isn't set but the pattern requires one.
    LocalStatic,
    /// The remote static key isn't set, it is a pre-message required
    /// by this pattern.
    RemoteStatic,
    /// The local ephemeral key isn't set but the pattern requires one (rare).
    LocalEphemeral,
    /// The remote ephemeral key isn't set, it is a pre-message required
    /// by this pattern.
    RemoteEphemeral,
    /// This pattern requires a Pre-Shared Key that wasn't provided to
    /// the builder.
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

/// The error types used by nivalis for the handshake and transport.
/// 
/// Implements [`core::error::Error`] and [`fmt::Display`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseError {
    /// Not all required keys where provided to the builder, see [`MissingKey`].
    MissingRequirements(MissingKey),
    /// A byte slice or value couldn't be converted to the expected type.
    ConversionError(&'static str),
    /// The user tried to send handshake messages after the handshake finished.
    HandshakeFinished,
    /// The input provided by the client is truncated or doesn't have
    /// the expected structure.
    InvalidInput(&'static str),
    /// The operation isn't valid for the current state.
    InvalidState(&'static str),
    /// Used in the tests when the required pattern/ciphersuite isn't supported.
    Unsupported(&'static str),
    /// The nonce counter has reached its maximum value (2^64 - 1) and
    /// cannot be incremented anymore.
    MaxNValue,
    /// Error happened during rekey. Ex: rekeying a key that isn't set yet.
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
