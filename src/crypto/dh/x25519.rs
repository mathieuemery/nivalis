//! X25519 implementation of the DH and DHKeypair traits

use anyhow::Result;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::crypto::dh::{DH, DHKeypair};

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

pub struct X25519dh;

impl DH for X25519dh {
    const DHLEN: usize = 32;
    const NAME: &'static str = "25519";

    type Keypair = X25519Keys;
    type PrivKey = StaticSecret;
    type PubKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn privkey_from_bytes(bytes: &[u8]) -> Result<Self::PrivKey> {
        let sk_bytes: [u8; Self::DHLEN] = bytes.try_into()?;
        Ok(From::from(sk_bytes))
    }

    fn pubkey_from_bytes(bytes: &[u8]) -> Result<Self::PubKey> {
        let arr: [u8; Self::DHLEN] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 56-byte X448 key, got {}", bytes.len()))?;
        Ok(PublicKey::from(arr))
    }

    fn pubkey_bytes(pk: &Self::PubKey) -> Vec<u8> {
        pk.as_bytes().to_vec()
    }

    fn generate_keypair() -> Self::Keypair {
        let private = StaticSecret::random();
        let public = PublicKey::from(&private);

        X25519Keys { public, private }
    }

    fn dh(sk: &Self::PrivKey, pk: &Self::PubKey) -> Self::SharedSecret {
        sk.diffie_hellman(pk)
    }
}
