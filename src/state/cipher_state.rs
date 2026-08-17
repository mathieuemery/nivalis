//! CipherState object of the Noise Handshake
//! https://noiseprotocol.org/noise.html#the-cipherstate-object

use anyhow::{Result, bail};

use crate::crypto::cipher::{Cipher, InternalCipherState};

const MAX_N_VALUE: u64 = (2 ^ 64) - 1;

#[derive(Debug)]
pub struct CipherState<C: Cipher> {
    pub k: Option<C::State>,
    pub n: u64,
}

impl<C: Cipher> CipherState<C> {
    pub fn initialize_key(key: Option<&[u8; 32]>) -> Self {
        Self {
            k: key.map(|k| C::init(k)),
            n: 0,
        }
    }

    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    pub fn set_nonce(mut self, nonce: u64) {
        self.n = nonce
    }

    pub fn encrypt_with_ad(&mut self, ad: &[u8], pt_buf: &[u8], buf: &mut [u8]) -> Result<usize> {
        if self.n + 1 == MAX_N_VALUE {
            bail!("N is already at the max value");
        }
        let size = if let Some(c) = &self.k {
            let size = c.encrypt(self.n, ad, pt_buf, buf)?;
            self.n += 1;
            size
        } else {
            buf[..pt_buf.len()].copy_from_slice(pt_buf);
            pt_buf.len()
        };

        Ok(size)
    }

    pub fn decrypt_with_ad(&mut self, ad: &[u8], ct_buf: &[u8], buf: &mut [u8]) -> Result<()> {
        if self.n + 1 == MAX_N_VALUE {
            bail!("N is already at the max value");
        }
        if let Some(c) = &self.k {
            c.decrypt(self.n, ad, ct_buf, buf)?;
            self.n += 1;
        } else {
            buf[..ct_buf.len()].copy_from_slice(ct_buf);
        }

        Ok(())
    }

    pub fn rekey(mut self) -> Result<()> {
        if let Some(c) = &mut self.k {
            c.rekey()?;
        } else {
            bail!("Cannot rekey a k that isn't set.")
        }

        Ok(())
    }

    pub fn from_parts(k: Option<C::State>, n: u64) -> Self {
        Self { k, n }
    }

    pub fn into_parts(self) -> (Option<C::State>, u64) {
        (self.k, self.n)
    }
}
