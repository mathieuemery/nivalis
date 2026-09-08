//! TransportState of the Noise Handshake

use core::marker::PhantomData;

use crate::crypto::cipher::Cipher;
use crate::crypto::dh::DH;
use crate::error::NoiseError;
use crate::patterns::roles::RoleMarker;
use crate::state::cipher_state::CipherState;

extern crate alloc;

use alloc::vec::Vec;

/// The Noise transport phrase, stores the pair of [`CipherState`] used
/// to encrypt/decrypt application data after the handshake completes.
/// 
/// Produced by [`SymmetricState::split`](crate::state::symmetric_state::SymmetricState::split)
/// via [`HandshakeState::write_message`](crate::state::handshake_state::HandshakeState::write_message)/
/// [`read_message`](crate::state::handshake_state::HandshakeState::read_message).
pub struct TransportState<C: Cipher, D: DH, R: RoleMarker> {
    local: CipherState<C>,
    remote: CipherState<C>,
    remote_pk: Option<D::PubKey>,
    _marker: PhantomData<R>
}

impl<C: Cipher, D: DH, R: RoleMarker> TransportState<C, D, R> {
    /// Creates a `TransportState` from the two CipherState's produced
    /// by `Split`.
    /// 
    /// `init` and `resp` must be passed in the same order as returned
    /// by `Split` (the initiator's cipher first, the responder's
    /// second)
    pub fn new(init: CipherState<C>, resp: CipherState<C>, remote_pk: Option<D::PubKey>) -> Self {
        if R::IS_INITIATOR {
            Self {
                local: init,
                remote: resp,
                remote_pk,
                _marker: PhantomData
            }
        } else {
            Self {
                local: resp,
                remote: init,
                remote_pk,
                _marker: PhantomData
            }
        }
    }

    /// Encrypts `pt_buf` with associated data `ad` for sending to the peer,
    /// writes the ciphertext into `buf`.
    /// 
    /// # Errors
    ///
    /// Returns [`NoiseError`] if the underlying cipher state's nonce
    /// is exhausted or encryption failed.
    pub fn encrypt_message(&mut self, ad: &[u8], pt_buf: &[u8], buf: &mut [u8]) -> Result<usize, NoiseError> {
        self.local.encrypt_with_ad(ad, pt_buf, buf)
    }

    /// Decrypts `ct_buf` with associated data `ad` for sending to the peer,
    /// writes the plaintext into `buf`.
    /// 
    /// # Errors
    ///
    /// Returns [`NoiseError`] if authentication fails, the nonce is exhausted, 
    /// or decryption failed.
    pub fn decrypt_message(&mut self, ad: &[u8], ct_buf: &[u8], buf: &mut [u8],) -> Result<(), NoiseError> {
        self.remote.decrypt_with_ad(ad, ct_buf, buf)
    }

    /// Returns the peer's static public key if it was learned during the handshake.
    pub fn remote_static_pk(&self) -> Option<Vec<u8>> {
        self.remote_pk.as_ref().map(D::pubkey_bytes)
    }
}