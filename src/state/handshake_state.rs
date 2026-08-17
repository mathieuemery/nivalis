//! HandshakeState of the noise handshake
//! https://noiseprotocol.org/noise.html#the-handshakestate-object

use std::marker::PhantomData;

use anyhow::{Context, Result, anyhow, bail};
use ring::aead::chacha20_poly1305_openssh::TAG_LEN;
use tracing::{debug, trace};

use crate::{
    constants::MAX_MESSAGE_LEN,
    crypto::{
        cipher::Cipher,
        dh::{DH, DHKeypair},
        hash::Hash,
    },
};

use crate::patterns::{Pattern, Token, roles::RoleMarker};
use crate::state::{cipher_state::CipherState, symmetric_state::SymmetricState};
use crate::types::Psk;

pub enum HandshakeResult<C: Cipher> {
    Continue {
        bytes: usize,
    },
    Complete {
        bytes_written: usize,
        initiator: CipherState<C>,
        responder: CipherState<C>,
        handshake_hash: Vec<u8>,
    },
}

pub struct HandshakeKeys<D: DH> {
    pub s: Option<D::Keypair>,
    pub e: Option<D::Keypair>,
    pub rs: Option<D::PubKey>,
    pub re: Option<D::PubKey>,
    pub psk: Option<Psk>,
}

fn checked_message_end(buf_index: usize, len: usize) -> Result<usize> {
    let end = buf_index
        .checked_add(len)
        .ok_or_else(|| anyhow!("Noise message length overflow"))?;

    if end > MAX_MESSAGE_LEN {
        bail!("Noise message is too large: {end} bytes (max {MAX_MESSAGE_LEN})");
    }

    Ok(end)
}

pub struct HandshakeState<P: Pattern, R: RoleMarker, D: DH, C: Cipher, H: Hash> {
    s_state: SymmetricState<C, H>,
    keys: HandshakeKeys<D>,
    e_set: bool,
    step: usize,
    psk_index: u8,
    _marker: PhantomData<(P, R)>,
}

impl<P: Pattern, R: RoleMarker, C: Cipher, D: DH, H: Hash> HandshakeState<P, R, D, C, H> {
    fn mix_pre_messages_init(
        state: &mut SymmetricState<C, H>,
        tokens: &[Token],
        s: Option<&D::Keypair>,
        e: Option<&D::Keypair>,
    ) -> Result<()> {
        for token in tokens {
            match token {
                Token::S => {
                    let s = s.ok_or_else(|| anyhow::anyhow!("Missing static key"))?;
                    state.mix_hash(&s.pubkey_bytes());
                }
                Token::E => {
                    let e = e.ok_or_else(|| anyhow::anyhow!("Missing ephemeral key"))?;
                    state.mix_hash(&e.pubkey_bytes());
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }

    fn mix_pre_messages_remote(
        state: &mut SymmetricState<C, H>,
        tokens: &[Token],
        rs: Option<&D::PubKey>,
        re: Option<&D::PubKey>,
    ) -> Result<()> {
        for token in tokens {
            match token {
                Token::S => {
                    let s = rs.ok_or_else(|| anyhow::anyhow!("Missing static key"))?;
                    state.mix_hash(&D::pubkey_bytes(s));
                }
                Token::E => {
                    let e = re.ok_or_else(|| anyhow::anyhow!("Missing ephemeral key"))?;
                    state.mix_hash(&D::pubkey_bytes(e));
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }

    /// Create a string with expected string structure
    /// ex: Noise_XX_25519_AESGCM_SHA256
    fn canonical_name() -> String {
        format!("Noise_{}_{}_{}_{}", P::NAME, D::NAME, C::NAME, H::NAME)
    }

    pub fn initialize(prologue: &[u8], keys: HandshakeKeys<D>) -> Result<Self> {
        let protocol_name = Self::canonical_name();

        let mut s_state = SymmetricState::initialize_symmetric(protocol_name.as_bytes());
        s_state.mix_hash(prologue);

        let pattern = P::HANDSHAKE;

        if R::IS_INITIATOR {
            Self::mix_pre_messages_init(
                &mut s_state,
                pattern.initiator_pre_messages(),
                keys.s.as_ref(),
                keys.e.as_ref(),
            )?;

            Self::mix_pre_messages_remote(
                &mut s_state,
                pattern.responder_pre_messages(),
                keys.rs.as_ref(),
                keys.re.as_ref(),
            )?;
        } else {
            Self::mix_pre_messages_remote(
                &mut s_state,
                pattern.initiator_pre_messages(),
                keys.rs.as_ref(),
                keys.re.as_ref(),
            )?;

            Self::mix_pre_messages_init(
                &mut s_state,
                pattern.responder_pre_messages(),
                keys.s.as_ref(),
                keys.e.as_ref(),
            )?;
        }

        Ok(Self {
            s_state,
            keys,
            e_set: false,
            step: 0,
            psk_index: 0,
            _marker: PhantomData,
        })
    }

    fn mix_ee(&mut self) -> Result<()> {
        let e = self
            .keys
            .e
            .as_ref()
            .ok_or_else(|| anyhow!("Missing e for ee at step {}", self.step))?;

        let re = self
            .keys
            .re
            .as_ref()
            .ok_or_else(|| anyhow!("Missing re for ee at step {}.", self.step))?;

        self.s_state.mix_key::<D>(D::dh(e.private(), re).as_ref());
        Ok(())
    }

    fn mix_es(&mut self) -> Result<()> {
        let dh_res = if R::IS_INITIATOR {
            let e = self
                .keys
                .e
                .as_ref()
                .ok_or_else(|| anyhow!("Missing e for es at step {}", self.step))?;
            let rs = self
                .keys
                .rs
                .as_ref()
                .ok_or_else(|| anyhow!("Missing rs for es at step {}", self.step))?;

            D::dh(e.private(), rs)
        } else {
            let s = self
                .keys
                .s
                .as_ref()
                .ok_or_else(|| anyhow!("Missing s for es at step {}", self.step))?;
            let re = self
                .keys
                .re
                .as_ref()
                .ok_or_else(|| anyhow!("Missing re for es at step {}", self.step))?;

            D::dh(s.private(), re)
        };

        self.s_state.mix_key::<D>(dh_res.as_ref());
        Ok(())
    }

    fn mix_se(&mut self) -> Result<()> {
        let dh_res = if R::IS_INITIATOR {
            let s = self
                .keys
                .s
                .as_ref()
                .ok_or_else(|| anyhow!("Missing s for se at step {}", self.step))?;
            let re = self
                .keys
                .re
                .as_ref()
                .ok_or_else(|| anyhow!("Missing re for se at step {}", self.step))?;

            D::dh(s.private(), re)
        } else {
            let e = self
                .keys
                .e
                .as_ref()
                .ok_or_else(|| anyhow!("Missing e for se at step {}", self.step))?;
            let rs = self
                .keys
                .rs
                .as_ref()
                .ok_or_else(|| anyhow!("Missing rs for se at step {}", self.step))?;

            D::dh(e.private(), rs)
        };

        self.s_state.mix_key::<D>(dh_res.as_ref());
        Ok(())
    }

    fn mix_ss(&mut self) -> Result<()> {
        let s = self
            .keys
            .s
            .as_ref()
            .ok_or_else(|| anyhow!("Missing s for ss at step {}", self.step))?;
        let rs = self
            .keys
            .rs
            .as_ref()
            .ok_or_else(|| anyhow!("Missing rs for ss at step {}", self.step))?;

        self.s_state.mix_key::<D>(D::dh(s.private(), rs).as_ref());
        Ok(())
    }

    /// Todo: Remove expect
    fn mix_psk(&mut self, psk_index: u8) -> Result<()> {
        let psk = self
            .keys
            .psk
            .ok_or_else(|| anyhow!("No PSK provided for index: {psk_index}"))?;

        self.s_state.mix_key_and_hash::<D>(&psk);

        Ok(())
    }

    pub fn write_message(
        &mut self,
        payload: &[u8],
        message_buffer: &mut [u8],
    ) -> Result<HandshakeResult<C>> {
        debug!(
            "[write_message] step {} for initiator ? {}",
            self.step,
            R::IS_INITIATOR
        );

        let messages = P::HANDSHAKE.messages();

        if self.step >= messages.len() {
            bail!("Handshake is already finished.");
        }

        let mut buf_index = 0;
        let next_message = &messages[self.step];

        for token in next_message.tokens {
            match token {
                Token::E => {
                    if self.e_set {
                        bail!("e must be empty");
                    }

                    let e: D::Keypair = match self.keys.e.take() {
                        Some(e) => e,
                        None => D::generate_keypair(),
                    };

                    let pk_bytes = e.pubkey_bytes();

                    let end = checked_message_end(buf_index, pk_bytes.len())?;

                    if message_buffer.len() < end {
                        bail!("Truncated message for e at step {}", self.step);
                    }

                    self.keys.e = Some(e);
                    self.e_set = true;

                    if message_buffer.len() < buf_index + pk_bytes.len() {
                        bail!("Truncated message for e at step {}", self.step);
                    }

                    message_buffer[buf_index..buf_index + pk_bytes.len()]
                        .copy_from_slice(&pk_bytes);

                    buf_index += pk_bytes.len();

                    self.s_state.mix_hash(&pk_bytes);

                    if P::HANDSHAKE.has_psk() {
                        self.s_state.mix_key::<D>(&pk_bytes);
                    }
                }
                Token::S => {
                    let pk_bytes = self
                        .keys
                        .s
                        .as_ref()
                        .ok_or_else(|| anyhow!("No static key provided"))?
                        .pubkey_bytes();

                    let s_len = pk_bytes
                        .len()
                        .checked_add(TAG_LEN)
                        .ok_or_else(|| anyhow!("Overflow during S pattern."))?;

                    let end = checked_message_end(buf_index, s_len)?;
                    if message_buffer.len() < end {
                        bail!("Message buffer is full");
                    }

                    if pk_bytes.len() + TAG_LEN > message_buffer.len() - buf_index {
                        bail!("Message buffer is full")
                    }

                    let n = self.s_state.encrypt_and_hash(
                        &pk_bytes,
                        &mut message_buffer[buf_index..buf_index + D::DHLEN + TAG_LEN],
                    )?;

                    trace!(
                        "Encrypted rs when writing: {:?}",
                        &message_buffer[buf_index..buf_index + D::DHLEN + TAG_LEN]
                    );

                    buf_index += n;
                }
                Token::EE => self.mix_ee()?,
                Token::ES => self.mix_es()?,
                Token::SE => self.mix_se()?,
                Token::SS => self.mix_ss()?,
                Token::PSK => {
                    self.mix_psk(self.psk_index)?;
                    self.psk_index += 1;
                }
            }
        }

        self.step += 1;

        if payload.len() > message_buffer.len() - buf_index {
            bail!("No place left for the payload")
        }

        let payload_ct_len = self
            .s_state
            .encrypt_and_hash(payload, &mut message_buffer[buf_index..])?;

        let end = checked_message_end(buf_index, payload_ct_len)?;
        if message_buffer.len() < end {
            bail!("Message is bigger than the maximum allowed");
        }

        buf_index = end;

        if self.step == messages.len() {
            let (c1, c2) = self.s_state.split::<D>();
            Ok(HandshakeResult::Complete {
                bytes_written: buf_index,
                initiator: c1,
                responder: c2,
                handshake_hash: self.s_state.get_handshake_hash()?,
            })
        } else {
            Ok(HandshakeResult::Continue { bytes: buf_index })
        }
    }

    pub fn read_message(
        &mut self,
        message: &[u8],
        payload_buffer: &mut [u8],
    ) -> Result<HandshakeResult<C>> {
        if message.len() > MAX_MESSAGE_LEN {
            bail!(
                "Received a message that is too long: {} when max is {MAX_MESSAGE_LEN}",
                message.len()
            )
        }
        debug!(
            "[read_message] step {} for initiator ? {}",
            self.step,
            R::IS_INITIATOR
        );
        let messages = P::HANDSHAKE.messages();

        if self.step >= messages.len() {
            bail!("Handshake is already finished.");
        }

        let mut buf_index = 0;
        let next_message = &messages[self.step];

        for token in next_message.tokens {
            match token {
                Token::E => {
                    if self.keys.re.is_some() {
                        bail!("re must be empty");
                    }

                    if message.len() < buf_index + D::DHLEN {
                        bail!("Truncated message for e.")
                    }

                    let re_bytes = &message[buf_index..buf_index + D::DHLEN];
                    buf_index += D::DHLEN;

                    let re = D::pubkey_from_bytes(re_bytes)
                        .context("re's bytes are not a valid public key")?;
                    self.keys.re = Some(re);

                    self.s_state.mix_hash(re_bytes);

                    if P::HANDSHAKE.has_psk() {
                        self.s_state.mix_key::<D>(re_bytes);
                    }
                }
                Token::S => {
                    let len = if self.s_state.c_state.has_key() {
                        D::DHLEN + 16
                    } else {
                        D::DHLEN
                    };

                    if message.len() < buf_index + len {
                        bail!("Truncated message for e.")
                    }

                    let temp = &message[buf_index..buf_index + len];
                    trace!("Encrypted rs when reading: {:?}", &temp);

                    buf_index += len;

                    let mut rs = vec![0u8; D::DHLEN + TAG_LEN];
                    self.s_state.decrypt_and_hash(temp, &mut rs)?;

                    self.keys.rs = Some(
                        D::pubkey_from_bytes(&rs[..D::DHLEN]).context("Invalid rs decrypted")?,
                    );
                }
                Token::EE => self.mix_ee()?,
                Token::ES => self.mix_es()?,
                Token::SE => self.mix_se()?,
                Token::SS => self.mix_ss()?,
                Token::PSK => {
                    self.mix_psk(self.psk_index)?;
                    self.psk_index += 1;
                }
            }
        }

        self.step += 1;

        trace!("Message len: {}, buf_index: {}", message.len(), buf_index);
        self.s_state
            .decrypt_and_hash(&message[buf_index..], payload_buffer)?;

        if self.step == messages.len() {
            let (c1, c2) = self.s_state.split::<D>();
            Ok(HandshakeResult::Complete {
                bytes_written: message.len(),
                initiator: c1,
                responder: c2,
                handshake_hash: self.s_state.get_handshake_hash()?,
            })
        } else {
            Ok(HandshakeResult::Continue { bytes: buf_index })
        }
    }
}
