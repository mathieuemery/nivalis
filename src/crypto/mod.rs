//! Cryptographic primitives used by the Noise handshake
//! (AEAD ciphers, DH and hash functions)
//!
//! Each submodule contains a trait describing the operations
//! that each function must provide and one or more 
//! implementations or them.

pub mod cipher;
pub mod dh;
pub mod hash;