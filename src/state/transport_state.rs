

use core::marker::PhantomData;

use crate::crypto::cipher::Cipher;
use crate::crypto::dh::DH;
use crate::error::NoiseError;
use crate::patterns::roles::RoleMarker;
use crate::state::cipher_state::CipherState;

extern crate alloc;

use alloc::vec::Vec;

pub struct TransportState<C: Cipher, D: DH, R: RoleMarker> {
    local: CipherState<C>,
    remote: CipherState<C>,
    remote_pk: Option<D::PubKey>,
    _marker: PhantomData<R>
}

impl<C: Cipher, D: DH, R: RoleMarker> TransportState<C, D, R> {
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

    pub fn encrypt_message(&mut self, ad: &[u8], pt_buf: &[u8], buf: &mut [u8]) -> Result<usize, NoiseError> {
        self.local.encrypt_with_ad(ad, pt_buf, buf)
    }

    pub fn decrypt_message(&mut self, ad: &[u8], ct_buf: &[u8], buf: &mut [u8],) -> Result<(), NoiseError> {
        self.remote.decrypt_with_ad(ad, ct_buf, buf)
    }

    pub fn remote_static_pk(&self) -> Option<Vec<u8>> {
        self.remote_pk.as_ref().map(D::pubkey_bytes)
    }
}