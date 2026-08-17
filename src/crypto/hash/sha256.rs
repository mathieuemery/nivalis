//! SHA256 implementation of the Hash trait

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256 as LibSha256};

use crate::crypto::hash::Hash;

type HmacSha256 = Hmac<LibSha256>;

pub struct Sha256;

impl Hash for Sha256 {
    const HASHLEN: usize = 32;
    const BLOCKLEN: usize = 64;
    const NAME: &'static str = "SHA256";

    type Output = [u8; Self::HASHLEN];

    fn pad(data: &[u8]) -> Self::Output {
        assert!(data.len() <= Self::HASHLEN);

        let mut output = [0u8; Self::HASHLEN];
        output[..data.len()].copy_from_slice(data);

        output
    }

    fn hash(data: &[u8]) -> Self::Output {
        LibSha256::digest(data).into()
    }

    fn hmac_hash(key: &[u8], data: &[u8]) -> Self::Output {
        let mut mac = HmacSha256::new_from_slice(key).expect("valid key length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}
