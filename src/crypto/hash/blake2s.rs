//! Blake2s implementation of the Hash trait

use blake2::{Blake2s256, Digest};
use hmac::{KeyInit, Mac, SimpleHmac};

use crate::crypto::hash::Hash;

type HmacBlake2s = SimpleHmac<Blake2s256>;

pub struct Blake2s;

impl Hash for Blake2s {
    const HASHLEN: usize = 32;
    const BLOCKLEN: usize = 64;
    const NAME: &'static str = "BLAKE2s";

    type Output = [u8; Self::HASHLEN];

    fn pad(data: &[u8]) -> Self::Output {
        assert!(data.len() <= Self::HASHLEN);

        let mut output = [0u8; Self::HASHLEN];
        output[..data.len()].copy_from_slice(data);

        output
    }

    fn hash(data: &[u8]) -> Self::Output {
        let mut hasher = Blake2s256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn hmac_hash(key: &[u8], data: &[u8]) -> Self::Output {
        let mut mac = HmacBlake2s::new_from_slice(key).expect("invalid key length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}
