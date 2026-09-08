//! X25519 implementation of the DH and DHKeypair traits

extern crate alloc;

use alloc::vec::Vec;
use rand_core::{Rng, CryptoRng};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::crypto::dh::{DH, DHKeypair};
use crate::error::NoiseError;

/// An X25519 keypair.
pub struct X25519Keys {
    pub public: PublicKey,
    private: StaticSecret,
}

impl DHKeypair for X25519Keys {
    type PrivKey = StaticSecret;
    type PubKey = PublicKey;

    fn public(&self) -> Self::PubKey {
        self.public
    }

    fn private(&self) -> &Self::PrivKey {
        &self.private
    }

    fn pubkey_bytes(&self) -> Vec<u8> {
        self.public.to_bytes().to_vec()
    }

    fn derive_keypair(sk: &Self::PrivKey) -> Self {
        let pk = PublicKey::from(sk);
        Self {
            private: sk.clone(),
            public: pk,
        }
    }
}

/// X25519 implementation of the Noise [`DH`] trait.
/// 
/// Based on the Montgomery curve Curve25519 as specified in
/// [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748).
pub struct X25519dh;

impl DH for X25519dh {
    const DHLEN: usize = 32;
    const NAME: &'static str = "25519";

    type Keypair = X25519Keys;
    type PrivKey = StaticSecret;
    type PubKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn privkey_from_bytes(bytes: &[u8]) -> Result<Self::PrivKey, NoiseError> {
        let sk_bytes: [u8; Self::DHLEN] = bytes
            .try_into()
            .map_err(|_| NoiseError::ConversionError("private key has wrong length for X25519"))?;

        Ok(From::from(sk_bytes))
    }

    /// Parses a public key from raw bytes.
    /// 
    /// # Errors
    /// 
    /// Returns [`NoiseError::ConversionError`] if `bytes` is not exactly 32 bytes.
    fn pubkey_from_bytes(bytes: &[u8]) -> Result<Self::PubKey, NoiseError> {
        let arr: [u8; Self::DHLEN] = bytes
            .try_into()
            .map_err(|_| NoiseError::ConversionError("public key has wrong length for X25519"))?;

        Ok(PublicKey::from(arr))
    }

    fn pubkey_bytes(pk: &Self::PubKey) -> Vec<u8> {
        pk.as_bytes().to_vec()
    }

    fn generate_keypair<R: Rng + CryptoRng>(rng: &mut R) -> Self::Keypair {
        let private = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&private);

        X25519Keys { public, private }
    }

    /// Performs a X25519 DH to derive a shared secret between a private key
    /// and a public key.
    fn dh(sk: &Self::PrivKey, pk: &Self::PubKey) -> Self::SharedSecret {
        sk.diffie_hellman(pk)
    }
}
