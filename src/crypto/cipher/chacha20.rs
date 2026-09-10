//! ChaCha20Poly1305 implementation of the Cipher and Cipherstate traits

use aes_gcm::AeadInOut;
use aes_gcm::aead::Error;
use chacha20poly1305::{ChaCha20Poly1305, Key, Tag};
use hmac::KeyInit;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::constants::{ENCRYPTION_KEY_LEN, TAG_LEN};
use crate::crypto::cipher::{Cipher, InternalCipherState, NONCE_LEN, Nonce};

/// Cipher state for [`ChaChaPoly`], stores the current 
/// encryption key (if any).
/// 
/// A `None` key is a valid state as the key isn't
/// always initialized.
#[derive(Clone, Debug)]
pub struct ChaChaPolyState {
    key: Option<Zeroizing<[u8; 32]>>,
}

/// ChaCha20-Poly1305 implementation of the Noise [`Cipher`] trait.
/// 
/// Uses a 96-bit nonce and a 128-bit tag as
/// specified by [RFC 8439](https://www.rfc-editor.org/info/rfc8439/)
pub struct ChaChaPoly;

impl Cipher for ChaChaPoly {
    const NAME: &'static str = "ChaChaPoly";
    type State = ChaChaPolyState;

    fn init(key: &[u8; ENCRYPTION_KEY_LEN]) -> Self::State {
        ChaChaPolyState { key: Some(Zeroizing::new(*key)) }
    }
}

impl InternalCipherState for ChaChaPolyState {
    /// Converts a Noise 64-bit nonce counter into the 12-byte nonce
    /// expected by ChaCha20-Poly1305.
    /// 
    /// This is 4 zero-bytes followed by the little-endian encoding of `n`.
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

            if buf.len() < pt_buf.len() + TAG_LEN {
                warn!("Provided output buffer is too small for encryption.");
                return Err(Error);
            }

            let key: &Key = key
                .as_ref()
                .try_into()
                .map_err(|_| Error)?;
            let cipher = ChaCha20Poly1305::new(key);

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

            if buf.len() < ct_buf.len() - TAG_LEN {
                warn!("Provided output buffer is too small for encryption.");
                return Err(Error);
            }

            let key: &Key = key
                .as_ref()
                .try_into()
                .map_err(|_| Error)?;
            let cipher = ChaCha20Poly1305::new(key);

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

        self.key = Some(Zeroizing::new(*key_bytes));

        Ok(())
    }
}
