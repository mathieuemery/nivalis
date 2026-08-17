//! Traits implemented by the AEAD algorithms

use std::fmt::Debug;

use aes_gcm::aead::Error;
use anyhow::Result;

use crate::constants::{ENCRYPTION_KEY_LEN, NONCE_LEN};
use crate::types::Nonce;

pub mod aesgcm;
pub mod chacha20;

pub trait Cipher {
    const NAME: &'static str;

    type State: InternalCipherState;

    fn init(key: &[u8; ENCRYPTION_KEY_LEN]) -> Self::State;
}

pub trait InternalCipherState: Clone + Debug {
    /// Convert the 64 byte nonce into a 96 byte nonce
    /// See Noise section 12.3 and 12.4
    fn convert_nonce(n: u64) -> Nonce;

    fn empty() -> Self;

    fn has_key(&self) -> bool;

    fn encrypt(&self, nonce: u64, ad: &[u8], pt_buf: &[u8], buf: &mut [u8])
    -> Result<usize, Error>;

    fn decrypt(&self, nonce: u64, ad: &[u8], ct_buf: &[u8], buf: &mut [u8]) -> Result<(), Error>;

    fn rekey(&mut self) -> Result<(), Error>;
}
