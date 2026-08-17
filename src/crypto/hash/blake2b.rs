//! Blake2b implementation of the Hash trait

use blake2::{Blake2b512, Digest};
use hmac::{KeyInit, Mac, SimpleHmac};

use crate::crypto::hash::Hash;

type HmacBlake2b = SimpleHmac<Blake2b512>;

pub struct Blake2b;

impl Hash for Blake2b {
    const HASHLEN: usize = 64;
    const BLOCKLEN: usize = 128;
    const NAME: &'static str = "BLAKE2b";

    type Output = [u8; Self::HASHLEN];

    fn pad(data: &[u8]) -> Self::Output {
        assert!(data.len() <= Self::HASHLEN);

        let mut output = [0u8; Self::HASHLEN];
        output[..data.len()].copy_from_slice(data);

        output
    }

    fn hash(data: &[u8]) -> Self::Output {
        let mut hasher = Blake2b512::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn hmac_hash(key: &[u8], data: &[u8]) -> Self::Output {
        let mut mac = HmacBlake2b::new_from_slice(key).expect("valid key length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}
