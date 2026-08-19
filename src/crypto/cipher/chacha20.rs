//! ChaCha20Poly1305 implementation of the Cipher and Cipherstate traits

use aes_gcm::AeadInOut;
use aes_gcm::aead::Error;
use chacha20poly1305::{ChaCha20Poly1305, Tag};
use hmac::KeyInit;
use tracing::debug;

use crate::constants::{ENCRYPTION_KEY_LEN, TAG_LEN};
use crate::crypto::cipher::{Cipher, InternalCipherState, NONCE_LEN, Nonce};

#[derive(Copy, Clone, Debug)]
pub struct ChaChaPolyState {
    key: Option<[u8; 32]>,
}

pub struct ChaChaPoly;

impl Cipher for ChaChaPoly {
    const NAME: &'static str = "ChaChaPoly";
    type State = ChaChaPolyState;

    fn init(key: &[u8; ENCRYPTION_KEY_LEN]) -> Self::State {
        ChaChaPolyState { key: Some(*key) }
    }
}

impl InternalCipherState for ChaChaPolyState {
    fn convert_nonce(n: u64) -> Nonce {
        let mut nonce: Nonce = [0u8; NONCE_LEN];
        nonce[4..NONCE_LEN].copy_from_slice(&n.to_le_bytes());

        nonce
    }

    fn empty() -> Self {
        Self { key: None }
    }

    fn has_key(&self) -> bool {
        self.key.is_some()
    }

    fn encrypt(&self, n: u64, ad: &[u8], pt_buf: &[u8], buf: &mut [u8]) -> Result<usize, Error> {
        let mut output_len = pt_buf.len();
        //println!("Encrypting with n = {n} and key = {:?}", self.key);
        if let Some(key) = &self.key {
            debug!("Nonce when encrypting: {}", n);

            let cipher = ChaCha20Poly1305::new(key.into());

            let nonce = Self::convert_nonce(n);
            buf[..pt_buf.len()].copy_from_slice(pt_buf);

            let tag = cipher.encrypt_inout_detached(
                &nonce.into(),
                ad,
                (&mut buf[..pt_buf.len()]).into(),
            )?;

            debug!("Encryption tag: {:?}", tag);

            buf[pt_buf.len()..pt_buf.len() + TAG_LEN].copy_from_slice(&tag);

            output_len += TAG_LEN;
        }

        Ok(output_len)
    }

    fn decrypt(&self, n: u64, ad: &[u8], ct_buf: &[u8], buf: &mut [u8]) -> Result<(), Error> {
        if let Some(key) = &self.key {
            debug!("Nonce when decrypting: {}", n);

            let cipher = ChaCha20Poly1305::new(key.into());

            let nonce = Self::convert_nonce(n);
            let pt_len = ct_buf.len() - TAG_LEN;

            if buf.len() < pt_len {
                return Err(Error);
            }

            let (ct, tag_bytes) = ct_buf.split_at(pt_len);

            // Copy only ciphertext
            buf[..pt_len].copy_from_slice(ct);

            let tag = Tag::try_from(tag_bytes).expect("Couldn't retrieve the tag for decryption");

            debug!("\nDecryption tag: {:?}\n", tag);

            cipher.decrypt_inout_detached(&nonce.into(), ad, (&mut buf[..pt_len]).into(), &tag)?;
        }

        debug!("Decryption successfull");

        Ok(())
    }

    fn rekey(&mut self) -> Result<(), Error> {
        let mut buf = [0u8; ENCRYPTION_KEY_LEN + TAG_LEN];

        self.encrypt(u64::MAX, &[], &[0u8; 32], &mut buf)?;

        let key_bytes: &[u8; ENCRYPTION_KEY_LEN] = buf[..ENCRYPTION_KEY_LEN]
            .try_into()
            .expect("incorrect key length");

        self.key = Some(*key_bytes);

        Ok(())
    }
}
