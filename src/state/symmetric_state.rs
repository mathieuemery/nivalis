//! SymmetricState object of the Noise Handshake
//! https://noiseprotocol.org/noise.html#the-symmetricstate-object

extern crate alloc;

use alloc::vec::Vec;
use tracing::trace;
use zeroize::Zeroizing;

use crate::constants::{ENCRYPTION_KEY_LEN, MAX_MESSAGE_LEN, TAG_LEN};
use crate::crypto::{cipher::Cipher, dh::DH, hash::Hash};
use crate::error::NoiseError;
use crate::state::cipher_state::CipherState;

/// The Noise `SymmetricState` object, stores the chaining key
/// and the hash. Wraps a [`CipherState`] for encrypting/decrypting
/// handshake messages.
/// 
/// Consumed via [`split`](Self::split) at the end of the handshake to
/// produce the pair of `CipherState`s used for transport encryption.
pub struct SymmetricState<C: Cipher, H: Hash> {
    c_state: CipherState<C>,
    ck: Zeroizing<H::Output>,
    h: H::Output,
    splitted: bool,
}

impl<C: Cipher, H: Hash> SymmetricState<C, H> {
    /// Create a new `SymmetricState` from the canonical protocol name
    /// string (ex: `Noise_XX_25519_AESGCM_SHA256`).
    /// 
    /// Sets both the chaining key `ck` and handshake hash `h` to
    /// `protocol_name` padded to `HASHLEN` is short enough or hashed
    /// otherwise.
    pub fn initialize_symmetric(protocol_name: &[u8]) -> Self {
        let h = if protocol_name.len() <= H::HASHLEN {
            H::pad(protocol_name)
        } else {
            H::hash(protocol_name)
        };

        trace!("Initializing cipherstate with None key");

        Self {
            c_state: CipherState::initialize_key(None),
            ck: Zeroizing::new(h.clone()),
            h,
            splitted: false,
        }
    }

    /// Mixes new key material into the chaining key and re-initializes
    /// the cipher state.
    /// 
    /// Called after each DH operation (`ee`, `es`, `se`, `ss`) during
    /// the handshake.
    pub fn mix_key<D: DH>(&mut self, input_key_material: &[u8]) {
        let (ck, temp_k) = H::hkdf2(self.ck.as_ref(), input_key_material, D::DHLEN);

        self.ck = Zeroizing::new(ck);

        // Instead of truncating, we know the key must always be 32 bytes
        let mut key = Zeroizing::new([0u8; ENCRYPTION_KEY_LEN]);
        key.copy_from_slice(&temp_k.as_ref()[..ENCRYPTION_KEY_LEN]);

        self.c_state = CipherState::initialize_key(Some(&key));
    }

    /// Mixes `data` into the handshake hash `h`.
    /// 
    /// Called for every public key and ciphertext exchanged
    /// during the handshake.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut result = Vec::with_capacity(H::HASHLEN + data.len());
        result.extend_from_slice(self.h.as_ref());
        result.extend_from_slice(data);

        self.h = H::hash(&result)
    }

    /// Mixes `input_key_material` into both the chaining key and the
    /// handshake hash and re-initializes the cipher state.
    /// 
    /// Used specifically for the `psk` token.
    pub fn mix_key_and_hash<D: DH>(&mut self, input_key_material: &[u8]) {
        let (ck, temp_h, temp_k) = H::hkdf3(self.ck.as_ref(), input_key_material, D::DHLEN);

        self.ck = Zeroizing::new(ck);
        self.mix_hash(temp_h.as_ref());

        let mut key = Zeroizing::new([0u8; ENCRYPTION_KEY_LEN]);
        key.copy_from_slice(&temp_k.as_ref()[..ENCRYPTION_KEY_LEN]);

        self.c_state = CipherState::initialize_key(Some(&key));
    }

    /// Returns the final handshake hash once the state has been splitted.
    /// 
    /// # Errors
    ///
    /// Returns [`NoiseError::InvalidState`] if called before
    /// [`split`](Self::split).
    pub fn get_handshake_hash(&self) -> Result<Vec<u8>, NoiseError> {
        if !self.splitted {
            return Err(NoiseError::InvalidState(
                "GetHandshakeHash() called before Split()",
            ));
        }

        Ok(self.h.as_ref().to_vec())
    }

    /// Encrypts the `plaintext` with the handshake hash as associated
    /// data, writes the result in `buf` and mixes the ciphertext into 
    /// the handshake hash.
    /// 
    /// # Errors
    ///
    /// Returns [`NoiseError::InvalidInput`] if the resulting
    /// ciphertext would exceed [`MAX_MESSAGE_LEN`], or if the
    /// underlying encryption fails.
    pub fn encrypt_and_hash(
        &mut self,
        plaintext: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, NoiseError> {
        let ct_len = plaintext
            .len()
            .checked_add(TAG_LEN)
            .ok_or(NoiseError::InvalidInput("message length overflow"))?;

        if ct_len > MAX_MESSAGE_LEN {
            return Err(NoiseError::InvalidInput("The message is too big}"));
        }

        let len = self
            .c_state
            .encrypt_with_ad(self.h.as_ref(), plaintext, buf)?;

        self.mix_hash(&buf[..len]);
        Ok(len)
    }

    /// Decrypts `ciphertext` with the handshake hash as associated
    /// data, writes the plaintext into `buf` and mixes the ciphertext
    /// into the handshake hash.
    /// 
    /// # Errors
    ///
    /// Returns [`NoiseError::InvalidInput`] if `ciphertext` exceeds
    /// [`MAX_MESSAGE_LEN`], or if decryption/authentication fails.
    pub fn decrypt_and_hash(
        &mut self,
        ciphertext: &[u8],
        buf: &mut [u8],
    ) -> Result<(), NoiseError> {
        if ciphertext.len() > MAX_MESSAGE_LEN {
            return Err(NoiseError::InvalidInput("The message is too long"));
        }
        self.c_state
            .decrypt_with_ad(self.h.as_ref(), ciphertext, buf)?;

        self.mix_hash(ciphertext);
        Ok(())
    }

    /// Split the `SymmetricState` into two `CipherState`s from the
    /// final chaining key. Marks this `SymmetricState` as splitted.
    pub fn split<D: DH>(&mut self) -> (CipherState<C>, CipherState<C>) {
        let (temp_k1, temp_k2) = H::hkdf2(self.ck.as_ref(), &[], D::DHLEN);

        let mut k1 = [0u8; ENCRYPTION_KEY_LEN];
        let mut k2 = [0u8; ENCRYPTION_KEY_LEN];

        k1.copy_from_slice(&temp_k1.as_ref()[..ENCRYPTION_KEY_LEN]);
        k2.copy_from_slice(&temp_k2.as_ref()[..ENCRYPTION_KEY_LEN]);

        self.splitted = true;

        (
            CipherState::initialize_key(Some(&k1)),
            CipherState::initialize_key(Some(&k2)),
        )
    }

    /// Returns `true` if the underlying cipher state's key
    /// is set.
    pub fn has_key(&self) -> bool {
        self.c_state.has_key()
    }
}
