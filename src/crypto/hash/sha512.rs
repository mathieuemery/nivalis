//! SHA512 implementation of the Hash trait

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha512 as LibSha512};

use crate::crypto::hash::Hash;

type HmacSha512 = Hmac<LibSha512>;

pub struct Sha512;

impl Hash for Sha512 {
    const HASHLEN: usize = 64;
    const BLOCKLEN: usize = 128;
    const NAME: &'static str = "SHA512";

    type Output = [u8; Self::HASHLEN];

    fn pad(data: &[u8]) -> Self::Output {
        assert!(data.len() <= Self::HASHLEN);

        let mut output = [0u8; Self::HASHLEN];
        output[..data.len()].copy_from_slice(data);

        output
    }

    fn hash(data: &[u8]) -> Self::Output {
        LibSha512::digest(data).into()
    }

    fn hmac_hash(key: &[u8], data: &[u8]) -> Self::Output {
        let mut mac = HmacSha512::new_from_slice(key).expect("valid key length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}
