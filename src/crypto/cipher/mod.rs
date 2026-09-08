//! Traits implemented by the AEAD algorithms

use core::fmt::Debug;

use aes_gcm::aead::Error;

use crate::constants::{ENCRYPTION_KEY_LEN, NONCE_LEN};
use crate::types::Nonce;

pub mod aesgcm;
pub mod chacha20;

/// A Noise cipher function: identifies the AEAD algorithm and
/// produces its [`InternalCipherState`].
/// 
/// See [`aesgcm::AesGcm`] and [`chacha20::ChaChaPoly`] for the two
/// implementations provided by this crate
pub trait Cipher {
    /// The Noise protocol name for this cipher (ex: "AESGCM",
    /// "ChaChaPoly"). Used when building the handshake's 
    /// protocol name string.
    const NAME: &'static str;

    /// The session state type produced by [`init`](Self::init),
    /// which performs the encryption/decryption.
    type State: InternalCipherState;

    /// Initializes the cipher state from a raw 256-bit encryption key
    fn init(key: &[u8; ENCRYPTION_KEY_LEN]) -> Self::State;
}

pub trait InternalCipherState: Clone + Debug {
    /// Convert the 64 byte nonce into a 96 byte nonce
    /// See Noise section 12.3 and 12.4
    fn convert_nonce(n: u64) -> Nonce;

    /// Returns an empty cipher state with no key set.
    fn empty() -> Self;

    /// Returns `true` if an encryption key has been set.
    fn has_key(&self) -> bool;

    /// Encrypts `pt_buf` in place into `buf`, appends the
    /// authentication tag and returns the number of bytes
    /// written (plaintext length + [`TAG_LEN`]).
    /// 
    /// `buf` must be at least `pt_buf.len() + TAG_LEN` bytes long.
    /// 
    /// # Note
    /// 
    /// If no key has been set, must return the plaintext un-encrypted
    /// as defined in the protocol and `buf` is left unmodified. Do not
    /// consider a successfull `Ok` as a proof that encryption occured.
    /// 
    /// # Errors
    /// 
    /// Returns [`aes_gcm::aead::Error`] if `buf` is too small or 
    /// encryption failed.
    fn encrypt(&self, nonce: u64, ad: &[u8], pt_buf: &[u8], buf: &mut [u8])
    -> Result<usize, Error>;

    /// Authenticate and decrypt `ct_buf` in place into `buf`.
    /// 
    /// `buf` must be at least `ct_buf.len() - TAG_LEN` bytes long.
    /// 
    /// # Note
    /// 
    /// If no key has been set, no decryption or tag validation is done
    /// and `buf` is left unmodified.
    /// 
    /// # Errors
    /// 
    /// Returns [`aes_gcm::aead::Error`] if `buf` is too small or if
    /// authentication or decryption failed.
    fn decrypt(&self, nonce: u64, ad: &[u8], ct_buf: &[u8], buf: &mut [u8]) -> Result<(), Error>;

    /// Rotates the current encryption key by encrypting 32 zero bytes
    /// under nonce `u64::MAX` and using the resulting ciphertext as
    /// the new key.
    /// 
    /// # Errors
    /// 
    /// Returns [`aes_gcm::aead::Error`] if the encryption failed.
    fn rekey(&mut self) -> Result<(), Error>;
}
