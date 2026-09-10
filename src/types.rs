//! Types used by other modules

use zeroize::Zeroizing;

use crate::constants::NONCE_LEN;

/// A Noise handshake nonce.
///
/// Used by the encryption method.
pub type Nonce = [u8; NONCE_LEN];

/// A Noise Pre-Shared Key
/// 
/// Used by some patterns where both parties
/// already have a shared secret
pub struct Psk(pub Zeroizing<[u8; 32]>);

impl Psk {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}