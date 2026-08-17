//! Traits implemented by the DH algorithms

use anyhow::Result;

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

    fn privkey_from_bytes(bytes: &[u8]) -> Result<Self::PrivKey>;

    fn pubkey_from_bytes(bytes: &[u8]) -> Result<Self::PubKey>;

    fn pubkey_bytes(pk: &Self::PubKey) -> Vec<u8>;

    fn generate_keypair() -> Self::Keypair;

    fn dh(sk: &Self::PrivKey, pk: &Self::PubKey) -> Self::SharedSecret;
}
