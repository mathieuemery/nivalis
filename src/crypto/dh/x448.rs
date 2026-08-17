//! X448 implementation of the DH and DHKeypair traits

use anyhow::Result;
use cx448::{MontgomeryPoint, Scalar, rand_core::OsRng, x448::x448};

use crate::crypto::dh::{DH, DHKeypair};

pub struct X448Keys {
    pub public: MontgomeryPoint,
    private: Scalar,
}

impl DHKeypair for X448Keys {
    type PrivKey = Scalar;
    type PubKey = MontgomeryPoint;

    fn public(&self) -> Self::PubKey {
        self.public
    }

    fn private(&self) -> &Self::PrivKey {
        &self.private
    }

    fn pubkey_bytes(&self) -> Vec<u8> {
        self.public.as_bytes().to_vec()
    }

    fn derive_keypair(sk: &Self::PrivKey) -> Self {
        let pk = x448(sk.to_bytes(), MontgomeryPoint::GENERATOR.0).expect("Couldn't derive the pk");
        Self {
            private: *sk,
            public: MontgomeryPoint(pk),
        }
    }
}

pub struct X448dh;

impl DH for X448dh {
    const DHLEN: usize = 56;
    const NAME: &'static str = "448";

    type Keypair = X448Keys;
    type PrivKey = Scalar;
    type PubKey = MontgomeryPoint;
    type SharedSecret = [u8; Self::DHLEN];

    fn privkey_from_bytes(bytes: &[u8]) -> Result<Self::PrivKey> {
        let sk_bytes: [u8; Self::DHLEN] = bytes.try_into()?;
        Ok(Scalar::from_bytes(&sk_bytes))
    }

    fn pubkey_from_bytes(bytes: &[u8]) -> Result<Self::PubKey> {
        let arr: [u8; Self::DHLEN] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 56-byte X448 key, got {}", bytes.len()))?;
        Ok(MontgomeryPoint(arr))
    }

    fn pubkey_bytes(pk: &Self::PubKey) -> Vec<u8> {
        pk.as_bytes().to_vec()
    }

    fn generate_keypair() -> Self::Keypair {
        let private = Scalar::random(&mut OsRng);
        let public = &private * &MontgomeryPoint::GENERATOR;

        X448Keys { public, private }
    }

    fn dh(sk: &Self::PrivKey, pk: &Self::PubKey) -> Self::SharedSecret {
        x448(sk.to_bytes(), pk.0).expect("Couldn't derive the pk")
    }
}
