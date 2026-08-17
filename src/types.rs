//! Types used by other modules

use crate::constants::NONCE_LEN;

pub type Nonce = [u8; NONCE_LEN];
pub type Psk = [u8; 32];
