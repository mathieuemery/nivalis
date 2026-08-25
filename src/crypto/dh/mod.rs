//! Traits implemented by the DH algorithms

extern crate alloc;

use alloc::vec::Vec;
use rand_core::{Rng, CryptoRng};

use crate::error::NoiseError;

pub mod x25519;
pub mod x448;

pub trait DHKeypair {
    type PrivKey;
    type PubKey;

    fn public(&self) -> Self::PubKey;
    fn private(&self) -> &Self::PrivKey;

    fn pubkey_bytes(&self) -> Vec<u8>;

    fn derive_keypair(sk: &Self::PrivKey) -> Self;
}

pub trait DH {
    const DHLEN: usize;
    const NAME: &'static str;

    type Keypair: DHKeypair<PrivKey = Self::PrivKey, PubKey = Self::PubKey>;
    type PrivKey;
    type PubKey;
    type SharedSecret: AsRef<[u8]>;

    fn privkey_from_bytes(bytes: &[u8]) -> Result<Self::PrivKey, NoiseError>;

    fn pubkey_from_bytes(bytes: &[u8]) -> Result<Self::PubKey, NoiseError>;

    fn pubkey_bytes(pk: &Self::PubKey) -> Vec<u8>;

    fn generate_keypair<R: Rng + CryptoRng>(rng: &mut R) -> Self::Keypair;

    fn dh(sk: &Self::PrivKey, pk: &Self::PubKey) -> Self::SharedSecret;
}
