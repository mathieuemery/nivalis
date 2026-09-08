//! CipherState of the Noise Handshake
//! 
//! https://noiseprotocol.org/noise.html#the-cipherstate-object

use crate::crypto::cipher::{Cipher, InternalCipherState};
use crate::error::NoiseError;

const MAX_N_VALUE: u64 = u64::MAX;

/// The Noise `CipherState` object, stores a cipher key
/// and a nonce counter to perform authenticated encryption/decryption
/// during and after the handshake.
#[derive(Debug)]
pub struct CipherState<C: Cipher> {
    k: Option<C::State>,
    n: u64,
}

impl<C: Cipher> CipherState<C> {
    /// Initializes a `CipherState` with an optional 256-bit key.
    pub fn initialize_key(key: Option<&[u8; 32]>) -> Self {
        Self {
            k: key.map(|k| C::init(k)),
            n: 0,
        }
    }

    /// Returns `true` if the key has been set.
    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    /// Sets the nonce counter to `nonce`
    pub fn set_nonce(&mut self, nonce: u64) {
        self.n = nonce
    }

    /// Encrypts `pt_buf` with associated data `ad`, writes
    /// the ciphertext into `buf` and returns the number of bytes
    /// written.
    /// 
    /// If no key is set, no encryption is done, `pt_buf` is
    /// copied into `buf` and the nonce isn't incremented.
    /// 
    /// # Errors
    /// 
    /// Returns [`NoiseError::MaxNValue`] if the nonce counter has
    /// reached its maximum value and cannot be incremented anymore, or
    /// [`NoiseError::InvalidInput`] if the cipher fails to encrypt
    /// (ex: `buf` is too small).
    pub fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        pt_buf: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, NoiseError> {
        if self.n + 1 == MAX_N_VALUE {
            return Err(NoiseError::MaxNValue);
        }
        let size = if let Some(c) = &self.k {
            let size = c
                .encrypt(self.n, ad, pt_buf, buf)
                .map_err(|_| NoiseError::InvalidInput("Couldn't encrypt the message"))?;
            self.n += 1;
            size
        } else {
            buf[..pt_buf.len()].copy_from_slice(pt_buf);
            pt_buf.len()
        };

        Ok(size)
    }

    /// Authenticate and decrypt `ct_buf` with associated data `ad` and
    /// writes the plaintext in `buf`.
    /// 
    /// If no key is set, `ct_buf` is copied into `buf` unmodified and
    /// the nonce is not incremented.
    /// 
    /// Returns [`NoiseError::MaxNValue`] if the nonce counter has
    /// reached its maximum value and cannot be incremented anymore, or
    /// [`NoiseError::InvalidInput`] if the cipher fails to decrypt
    /// (ex: tampered ciphertext).
    pub fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ct_buf: &[u8],
        buf: &mut [u8],
    ) -> Result<(), NoiseError> {
        if self.n + 1 == MAX_N_VALUE {
            return Err(NoiseError::MaxNValue);
        }
        if let Some(c) = &self.k {
            c.decrypt(self.n, ad, ct_buf, buf)
                .map_err(|_| NoiseError::InvalidInput("Couldn't decrypt the message"))?;
            self.n += 1;
        } else {
            buf[..ct_buf.len()].copy_from_slice(ct_buf);
        }

        Ok(())
    }

    /// Rotates the cipher key.
    /// 
    /// # Errors
    /// 
    /// Returns [`NoiseError::Rekey`] if no key is currently set, or
    /// [`NoiseError::InvalidInput`] if the underlying rekey operation
    /// fails.
    pub fn rekey(&mut self) -> Result<(), NoiseError> {
        if let Some(c) = &mut self.k {
            c.rekey().map_err(|_| NoiseError::InvalidInput("Couldn't do the rekey"))?
        } else {
            return Err(NoiseError::Rekey("Cannot rekey a k that isn't set."));
        }

        Ok(())
    }

    /// Reconstructs a `CipherState` from a given key and nonce.
    /// 
    /// Primarily used for tests.
    pub fn from_parts(k: Option<C::State>, n: u64) -> Self {
        Self { k, n }
    }

    /// Decomposes this `CipherState` into its raw key and nonce parts.
    /// 
    /// The inverse of [`from_parts`](Self::from_parts)
    pub fn into_parts(self) -> (Option<C::State>, u64) {
        (self.k, self.n)
    }
}
