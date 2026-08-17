//! Traits implemented by the hash functions

pub mod blake2b;
pub mod blake2s;
pub mod sha256;
pub mod sha512;

pub trait Hash {
    const HASHLEN: usize;
    const BLOCKLEN: usize;
    const NAME: &'static str;

    type Output: Copy + AsRef<[u8]>;

    /// Doesn't create a hash
    fn pad(data: &[u8]) -> Self::Output;

    fn hash(data: &[u8]) -> Self::Output;

    fn hmac_hash(key: &[u8], data: &[u8]) -> Self::Output;

    fn hkdf(
        chaining_key: &[u8],
        ikm: &[u8],
        dh_len: usize,
        num_outputs: usize,
    ) -> Vec<Self::Output> {
        assert_eq!(
            chaining_key.len(),
            Self::HASHLEN,
            "Chaining key must have length HASHLEN. Expected {}, got {}",
            Self::HASHLEN,
            chaining_key.len()
        );

        assert!(
            [0, 32, dh_len].contains(&ikm.len()),
            "IKM must be either 0, 32 or DHLEN. Got: {}",
            ikm.len()
        );

        let temp_key = Self::hmac_hash(chaining_key, ikm);

        let output1 = Self::hmac_hash(temp_key.as_ref(), &[0x01]);

        let mut input2 = Vec::with_capacity(Self::HASHLEN + 1);
        input2.extend_from_slice(output1.as_ref());
        input2.push(0x02);
        let output2 = Self::hmac_hash(temp_key.as_ref(), &input2);

        let mut result = vec![output1, output2];

        if num_outputs == 3 {
            let mut input3 = Vec::with_capacity(Self::HASHLEN + 1);
            input3.extend_from_slice(output2.as_ref());
            input3.push(0x03);
            let output3 = Self::hmac_hash(temp_key.as_ref(), &input3);
            result.push(output3);
        }

        result
    }

    fn hkdf2(chaining_key: &[u8], ikm: &[u8], dh_len: usize) -> (Self::Output, Self::Output) {
        let mut keys = Self::hkdf(chaining_key, ikm, dh_len, 2);

        assert_eq!(keys.len(), 2);
        (keys.remove(0), keys.remove(0))
    }

    fn hkdf3(
        chaining_key: &[u8],
        ikm: &[u8],
        dh_len: usize,
    ) -> (Self::Output, Self::Output, Self::Output) {
        let mut keys = Self::hkdf(chaining_key, ikm, dh_len, 3);

        assert_eq!(keys.len(), 3);
        (keys.remove(0), keys.remove(0), keys.remove(0))
    }
}
