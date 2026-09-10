//! Traits implemented by the DH algorithms

extern crate alloc;

use alloc::vec::Vec;
use rand_core::{Rng, CryptoRng};

use crate::error::NoiseError;

pub mod x25519;
pub mod x448;

/// A DH keypair.
/// 
/// See [`x25519`] and [`x448`] for the two DH
/// functions provided by this crate.
pub trait DHKeypair {
    /// The private key of this keypair.
    type PrivKey;
    /// The public key of this keypair.
    type PubKey;

    /// Returns the public key for this keypair.
    fn public(&self) -> Self::PubKey;

    /// Returns a reference to the private key for this keypair.
    fn private(&self) -> &Self::PrivKey;

    /// Returns the public key encoded as bytes.
    fn pubkey_bytes(&self) -> Vec<u8>;

    /// Derive a keypair from an existing private key.
    fn derive_keypair(sk: Self::PrivKey) -> Self;
}

/// A Noise `DH` function.
/// 
/// See [`x25519`] and [`x448`] for the two DH
/// functions provided by this crate.
pub trait DH {
    /// The length in bytes of the DH output for this algorithm (ex: 32 for
    /// X25519 and 56 for X448)
    const DHLEN: usize;
    /// The Noise protocol name for this DH function. Used when
    /// building the handshake's protocol name string.
    const NAME: &'static str;

    /// The keypair type associated with the function.
    type Keypair: DHKeypair<PrivKey = Self::PrivKey, PubKey = Self::PubKey>;
    /// The private key type for this DH function.
    type PrivKey;
    /// The public key type for this DH function.
    type PubKey;
    /// The shared secret produced by [`dh`](Self::dh)
    type SharedSecret: AsRef<[u8]>;

    /// Parses a private key from its byte encoding.
    /// 
    /// # Errors
    /// 
    /// Returns [`NoiseError`] if `bytes` is not a valid encoding for
    /// this algorithm's private key (ex: wrong length).
    fn privkey_from_bytes(bytes: &[u8]) -> Result<Self::PrivKey, NoiseError>;

    /// Parses a public key from its byte encoding.
    /// 
    /// # Errors
    /// 
    /// Returns [`NoiseError`] if `bytes` is not a valid encoding for
    /// this algorithm's public key (ex: wrong length).
    fn pubkey_from_bytes(bytes: &[u8]) -> Result<Self::PubKey, NoiseError>;

    /// Returns the public key encoded as bytes.
    fn pubkey_bytes(pk: &Self::PubKey) -> Vec<u8>;

    /// Generate a new random keypair using the provided
    /// cryptographically secure RNG.
    fn generate_keypair<R: Rng + CryptoRng>(rng: &mut R) -> Self::Keypair;

    /// Performs a DH between the local private key and a remote
    /// public key.
    fn dh(sk: &Self::PrivKey, pk: &Self::PubKey) -> Self::SharedSecret;
}
