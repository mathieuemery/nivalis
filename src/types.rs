//! Types used by other modules

use crate::constants::NONCE_LEN;

/// A Noise handshake nonce.
///
/// Used by the encryption method.
pub type Nonce = [u8; NONCE_LEN];

/// A Noise Pre-Shared Key
/// 
/// Used by some patterns where both parties
/// already have a shared secret
pub type Psk = [u8; 32];
