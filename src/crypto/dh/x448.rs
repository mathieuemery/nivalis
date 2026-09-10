//! X448 implementation of the DH and DHKeypair traits

extern crate alloc;

use alloc::vec::Vec;
use cx448::{MontgomeryPoint, Scalar, WideScalarBytes, x448::x448};
use rand_core::{Rng, CryptoRng};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::dh::{DH, DHKeypair};
use crate::error::NoiseError;

/// An X448 keypair.
pub struct X448Keys {
    pub public: MontgomeryPoint,
    private: Scalar,
}

impl Drop for X448Keys {
    fn drop(&mut self) {
        self.private.zeroize();
    }
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

    /// Derive a keypair by multiplying the scalar `sk` with the
    /// standard x448 base point.
    /// 
    /// # Panics
    /// 
    /// Panics if the X448 multiplication fails. Shouldn't happen as the error
    /// is thrown if `point_bytes` is malformed.
    fn derive_keypair(sk: Self::PrivKey) -> Self {
        let pk = x448(sk.to_bytes(), MontgomeryPoint::GENERATOR.0).expect("Couldn't derive the pk");
        Self {
            private: sk,
            public: MontgomeryPoint(pk),
        }
    }
}


/// X448 implementation of the Noise [`DH`] trait.
/// 
/// Based on the Montgomery curve Curve448 as specified in
/// [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748).
pub struct X448dh;

impl DH for X448dh {
    const DHLEN: usize = 56;
    const NAME: &'static str = "448";

    type Keypair = X448Keys;
    type PrivKey = Scalar;
    type PubKey = MontgomeryPoint;
    type SharedSecret = Zeroizing<[u8; Self::DHLEN]>;

    fn privkey_from_bytes(bytes: &[u8]) -> Result<Self::PrivKey, NoiseError> {
        let sk_bytes: [u8; Self::DHLEN] = bytes
            .try_into()
            .map_err(|_| NoiseError::ConversionError("private key has wrong length for X448"))?;

        Ok(Scalar::from_bytes(&sk_bytes))
    }

    /// Parses a public key from raw bytes.
    /// 
    /// # Errors
    /// 
    /// Returns [`NoiseError::ConversionError`] if `bytes` is not exactly 56 bytes.
    fn pubkey_from_bytes(bytes: &[u8]) -> Result<Self::PubKey, NoiseError> {
        let arr: [u8; Self::DHLEN] = bytes
            .try_into()
            .map_err(|_| NoiseError::ConversionError("public key has wrong length for X448"))?;

        Ok(MontgomeryPoint(arr))
    }

    fn pubkey_bytes(pk: &Self::PubKey) -> Vec<u8> {
        pk.as_bytes().to_vec()
    }

    fn generate_keypair<R: Rng + CryptoRng>(rng: &mut R) -> Self::Keypair {
        // Cannot use Scalar::random(&mut OsRng) as it uses incompatible version
        // of rand_core
        let mut wide_bytes = WideScalarBytes::default();
        rng.fill_bytes(&mut wide_bytes);

        let private = Scalar::from_bytes_mod_order_wide(&wide_bytes);
        wide_bytes.zeroize();

        let public = &private * &MontgomeryPoint::GENERATOR;

        X448Keys { public, private }
    }

    /// Performs a X448 DH to derive a shared secret between a private key
    /// and a public key.
    /// 
    /// # Panics
    /// 
    /// Panics if the public key doesn't have the correct format.
    fn dh(sk: &Self::PrivKey, pk: &Self::PubKey) -> Self::SharedSecret {
        Zeroizing::new(
            x448(sk.to_bytes(), pk.0)
                .expect("Couldn't derive the pk")
        )
    }
}
