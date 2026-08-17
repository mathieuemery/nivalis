//! SymmetricState object of the Noise Handshake
//! https://noiseprotocol.org/noise.html#the-symmetricstate-object

use anyhow::{Result, anyhow, bail};
use ring::aead::chacha20_poly1305_openssh::TAG_LEN;
use tracing::trace;

use crate::constants::{ENCRYPTION_KEY_LEN, MAX_MESSAGE_LEN};
use crate::crypto::{cipher::Cipher, dh::DH, hash::Hash};
use crate::state::cipher_state::CipherState;

pub struct SymmetricState<C: Cipher, H: Hash> {
    c_state: CipherState<C>,
    ck: H::Output,
    h: H::Output,
    splitted: bool,
}

impl<C: Cipher, H: Hash> SymmetricState<C, H> {
    pub fn initialize_symmetric(protocol_name: &[u8]) -> Self {
        let h = if protocol_name.len() <= H::HASHLEN {
            H::pad(protocol_name)
        } else {
            H::hash(protocol_name)
        };

        trace!("Initializing cipherstate with None key");

        Self {
            c_state: CipherState::initialize_key(None),
            ck: h,
            h,
            splitted: false,
        }
    }

    pub fn mix_key<D: DH>(&mut self, input_key_material: &[u8]) {
        let (ck, temp_k) = H::hkdf2(self.ck.as_ref(), input_key_material, D::DHLEN);

        self.ck = ck;

        // Instead of truncating, we know the key must always be 32 bytes
        let mut key = [0u8; ENCRYPTION_KEY_LEN];
        key.copy_from_slice(&temp_k.as_ref()[..ENCRYPTION_KEY_LEN]);

        self.c_state = CipherState::initialize_key(Some(&key));
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut result = Vec::with_capacity(H::HASHLEN + data.len());
        result.extend_from_slice(self.h.as_ref());
        result.extend_from_slice(data);

        self.h = H::hash(&result)
    }

    pub fn mix_key_and_hash<D: DH>(&mut self, input_key_material: &[u8]) {
        let (ck, temp_h, temp_k) = H::hkdf3(self.ck.as_ref(), input_key_material, D::DHLEN);

        self.ck = ck;
        self.mix_hash(temp_h.as_ref());

        let mut key = [0u8; ENCRYPTION_KEY_LEN];
        key.copy_from_slice(&temp_k.as_ref()[..ENCRYPTION_KEY_LEN]);

        self.c_state = CipherState::initialize_key(Some(&key));
    }

    pub fn get_handshake_hash(&self) -> Result<Vec<u8>> {
        if !self.splitted {
            bail!("GetHandshakeHash() called before Split()")
        }

        Ok(self.h.as_ref().to_vec())
    }

    /// CT isn't returned as spec defines because it mutates an output buffer
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8], buf: &mut [u8]) -> Result<usize> {
        let ct_len = plaintext
            .len()
            .checked_add(TAG_LEN)
            .ok_or_else(|| anyhow!("message length overflow"))?;

        if ct_len > MAX_MESSAGE_LEN {
            bail!("The message is too big: {ct_len} when max is {MAX_MESSAGE_LEN}");
        }

        match self
            .c_state
            .encrypt_with_ad(self.h.as_ref(), plaintext, buf)
        {
            Ok(len) => {
                self.mix_hash(&buf[..len]);
                Ok(len)
            }
            Err(e) => bail!("Couldn't encrypt and hash the plaintext: {e}"),
        }
    }

    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> Result<()> {
        if ciphertext.len() > MAX_MESSAGE_LEN {
            bail!(
                "The message is too big: {} when max is {MAX_MESSAGE_LEN}",
                ciphertext.len()
            )
        }
        match self
            .c_state
            .decrypt_with_ad(self.h.as_ref(), ciphertext, buf)
        {
            Ok(_) => {
                self.mix_hash(ciphertext);
                Ok(())
            }
            Err(e) => bail!("Couldn't decrypt and hash the ciphertext: {e}"),
        }
    }

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

    pub fn has_key(&self) -> bool {
        self.c_state.has_key()
    }
}
