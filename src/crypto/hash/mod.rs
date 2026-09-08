//! Traits implemented by the hash functions

extern crate alloc;
use alloc::{vec, vec::Vec};

pub mod blake2b;
pub mod blake2s;
pub mod sha256;
pub mod sha512;

/// A Noise `HASH` function.
/// 
/// See [`blake2b`], [`blake2s`], [`sha256`] and [`sha512`]
/// for the four hash functions provided by this crate.
pub trait Hash {
    /// The length in bytes of this hash function's output
    /// (ex: 32 for SHA-256, 64 for SHA-512).
    const HASHLEN: usize;
    /// The internal block length in bytes of this hash function.
    /// Used for HMAC padding.
    const BLOCKLEN: usize;
    /// The Noise protocol name for this hash function. Used when
    /// building the handshake's protocol name string.
    const NAME: &'static str;

    /// The output type of this hash function.
    type Output: Copy + AsRef<[u8]>;

    /// Pads `data` to a multiple of [`HASHLEN`](Self::HASHLEN).
    /// 
    /// This does not compute a hash digest, it only produces a padded block.
    fn pad(data: &[u8]) -> Self::Output;

    /// Computes the hash digest of `data
    fn hash(data: &[u8]) -> Self::Output;

    /// Computes `HMAC-HASH(key, data)` as defined in
    /// [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104), using this
    /// hash function.
    fn hmac_hash(key: &[u8], data: &[u8]) -> Self::Output;

    /// Computes `HKDF(chaining_key, input_key_material, num_outputs)`
    /// as defined in Noise spec section 4.3 / [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869).
    /// 
    /// Most callers should use [`hkdf2`](Self::hkdf2) or [`hkdf3`](Self::hkdf3) which
    /// will then call this method to get the outputs.
    /// 
    /// # Panics
    /// 
    /// Panics if `chaining_key.len() != HASHLEN`, or if `ikm.len()` is
    /// not one of `0`, `32`, or `dh_len` as defined in the Noise protocol.
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

    /// Wrapper around [`hkdf`](Self::hkdf) that returns exactly two outputs.
    /// 
    /// # Panics
    /// 
    /// Panics under the same conditions as [`hkdf`](Self::hkdf).
    fn hkdf2(chaining_key: &[u8], ikm: &[u8], dh_len: usize) -> (Self::Output, Self::Output) {
        let mut keys = Self::hkdf(chaining_key, ikm, dh_len, 2);

        assert_eq!(keys.len(), 2);
        (keys.remove(0), keys.remove(0))
    }

    /// Wrapper around [`hkdf`](Self::hkdf) that returns exactly two outputs.
    /// Used when mixing in a pre-shared key.
    /// 
    /// # Panics
    /// 
    /// Panics under the same conditions as [`hkdf`](Self::hkdf).
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
