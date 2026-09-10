//! HandshakeState of the noise handshake
//! 
//! https://noiseprotocol.org/noise.html#the-handshakestate-object

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};
use core::marker::PhantomData;
use rand_core::{Rng as Random, CryptoRng};
use tracing::{debug, trace};

use crate::{
    constants::{MAX_MESSAGE_LEN, TAG_LEN}, crypto::{
        cipher::Cipher,
        dh::{DH, DHKeypair},
        hash::Hash,
    }, error::{MissingKey, NoiseError}, state::transport_state::TransportState,
};

use crate::patterns::{Pattern, Token, roles::RoleMarker};
use crate::state::symmetric_state::SymmetricState;
use crate::types::Psk;

/// The outcome of a single [`HandshakeState::write_message`] or
/// [`HandshakeState::read_message`] call.
pub enum HandshakeResult<C: Cipher, D: DH, R: RoleMarker> {
    /// The handshake message was processed successfully but the
    /// handshake isn't finished yet.
    Continue {
        /// The number of bytes written to (or consumed from) the message
        /// buffer for this step.
        bytes: usize,
    },
    /// The final handshake message was processed, the handshake is finished
    /// and transport encryption can begin.
    Complete {
        /// The number of bytes written to (or consumed from) the message
        /// buffer for the final step.
        bytes_written: usize,
        /// The resulting [`TransportState`] used to encrypt/decrypt
        /// application data after the handshake.
        transport_state: TransportState<C, D, R>,
        /// The final hash of the handshake (`h`).
        handshake_hash: Vec<u8>,
    },
}

/// The key material given by the user for the handshake.
///
/// Which fields are required depends on the chosen
/// [`Pattern`]/[`RoleMarker`].
pub struct HandshakeKeys<D: DH> {
    /// The local static keypair.
    pub s: Option<D::Keypair>,
    /// The local ephemeral keypair.
    pub e: Option<D::Keypair>,
    /// The remote static public key.
    pub rs: Option<D::PubKey>,
    /// The remote ephemeral public key.
    pub re: Option<D::PubKey>,
    /// The pre-shared key.
    pub psk: Option<Psk>,
}

impl<D: DH> HandshakeKeys<D> {
    fn clear(&mut self) {
        self.s.take();
        self.e.take();
        self.rs.take();
        self.re.take();
        self.psk.take();
    }
}

/// Computes `buf_index + len`, checking for both integer overflow and
/// the Noise spec's maximum message length ([`MAX_MESSAGE_LEN`]).
fn checked_message_end(buf_index: usize, len: usize) -> Result<usize, NoiseError> {
    let end = buf_index
        .checked_add(len)
        .ok_or(NoiseError::InvalidInput("Noise message length overflow"))?;

    if end > MAX_MESSAGE_LEN {
        return Err(NoiseError::InvalidInput("Noise message is too large."))
    }

    Ok(end)
}

/// The Noise `HandshakeState` object, drives the handshake message sequence
/// for a given [`Pattern`], [`RoleMarker`], DH function, cipher and hash.
/// 
/// Created via [`HandshakeState::initialize`] generally called by
/// [`HandshakeParamsBuilder::build()`].
pub struct HandshakeState<P: Pattern, R: RoleMarker, D: DH, C: Cipher, H: Hash> {
    s_state: SymmetricState<C, H>,
    keys: HandshakeKeys<D>,
    e_set: bool,
    step: usize,
    _marker: PhantomData<(P, R)>,
}

impl<P: Pattern, R: RoleMarker, C: Cipher, D: DH, H: Hash> HandshakeState<P, R, D, C, H> {
    /// Mixes the local party's own pre-message keys into the handshake.
    /// 
    /// # Errors
    /// 
    /// Returns [`NoiseError::MissingRequirements`] if a pre-message
    /// token requires a key that wasn't supplied.
    fn mix_pre_messages_init(
        state: &mut SymmetricState<C, H>,
        tokens: &[Token],
        s: Option<&D::Keypair>,
        e: Option<&D::Keypair>,
    ) -> Result<(), NoiseError> {
        for token in tokens {
            match token {
                Token::S => {
                    let s =
                        s.ok_or(NoiseError::MissingRequirements(MissingKey::LocalStatic))?;
                    state.mix_hash(&s.pubkey_bytes());
                }
                Token::E => {
                    let e = e.ok_or({
                        NoiseError::MissingRequirements(MissingKey::LocalEphemeral)
                    })?;
                    state.mix_hash(&e.pubkey_bytes());
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }

    /// Mixes the peer's pre-message keys into the handshake.
    /// 
    /// # Errors
    /// 
    /// Returns [`NoiseError::MissingRequirements`] if a pre-message
    /// token requires a key that wasn't supplied.
    fn mix_pre_messages_remote(
        state: &mut SymmetricState<C, H>,
        tokens: &[Token],
        rs: Option<&D::PubKey>,
        re: Option<&D::PubKey>,
    ) -> Result<(), NoiseError> {
        for token in tokens {
            match token {
                Token::S => {
                    let s =
                        rs.ok_or(NoiseError::MissingRequirements(MissingKey::RemoteStatic))?;
                    state.mix_hash(&D::pubkey_bytes(s));
                }
                Token::E => {
                    let e = re.ok_or({
                        NoiseError::MissingRequirements(MissingKey::RemoteEphemeral)
                    })?;
                    state.mix_hash(&D::pubkey_bytes(e));
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }

    /// Creates the canonical Noise protocol name sting,
    /// ex: `Noise_XX_25519_AESGCM_SHA256`. Used to initialize the
    /// symmetric state.
    fn canonical_name() -> String {
        format!("Noise_{}_{}_{}_{}", P::NAME, D::NAME, C::NAME, H::NAME)
    }

    /// Creates a new `HandshakeState` from a given `prologue` and `keys`.
    /// 
    /// This is normally called via
    /// [`HandshakeParamsBuilder::build`](crate::builder::HandshakeParamsBuilder::build)
    /// rather than directly.
    /// 
    /// # Errors
    /// 
    /// Returns [`NoiseError::MissingRequirements`] if `keys` is missing
    /// a key required by `P`'s pre-messages for either role.
    pub fn initialize(prologue: &[u8], keys: HandshakeKeys<D>) -> Result<Self, NoiseError> {
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
            _marker: PhantomData,
        })
    }

    /// Performs the `ee` DH token: mixes `DH(local_ephemeral,
    /// remote_ephemeral)` into the symmetric state's chaining key.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError::MissingRequirements`] if either ephemeral
    /// key is missing.
    fn mix_ee(&mut self) -> Result<(), NoiseError> {
        let e = self
            .keys
            .e
            .as_ref()
            .ok_or(NoiseError::MissingRequirements(MissingKey::LocalEphemeral))?;

        let re = self
            .keys
            .re
            .as_ref()
            .ok_or(NoiseError::MissingRequirements(MissingKey::RemoteEphemeral))?;

        self.s_state.mix_key::<D>(D::dh(e.private(), re).as_ref());
        Ok(())
    }

    /// Performs the `es` DH token depending on who is executing, then mix the result
    /// into the symmetric state's chaining key.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError::MissingRequirements`] if the required
    /// local or remote key is missing.
    fn mix_es(&mut self) -> Result<(), NoiseError> {
        let dh_res =
            if R::IS_INITIATOR {
                let e =
                    self.keys.e.as_ref().ok_or({
                        NoiseError::MissingRequirements(MissingKey::LocalEphemeral)
                    })?;
                let rs = self
                    .keys
                    .rs
                    .as_ref()
                    .ok_or(NoiseError::MissingRequirements(MissingKey::RemoteStatic))?;

                D::dh(e.private(), rs)
            } else {
                let s = self
                    .keys
                    .s
                    .as_ref()
                    .ok_or(NoiseError::MissingRequirements(MissingKey::LocalStatic))?;
                let re =
                    self.keys.re.as_ref().ok_or({
                        NoiseError::MissingRequirements(MissingKey::RemoteEphemeral)
                    })?;

                D::dh(s.private(), re)
            };

        self.s_state.mix_key::<D>(dh_res.as_ref());
        Ok(())
    }

    /// Performs the `se` DH token depending on who is executing, then mix the result
    /// into the symmetric state's chaining key.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError::MissingRequirements`] if the required
    /// local or remote key is missing.
    fn mix_se(&mut self) -> Result<(), NoiseError> {
        let dh_res =
            if R::IS_INITIATOR {
                let s = self
                    .keys
                    .s
                    .as_ref()
                    .ok_or(NoiseError::MissingRequirements(MissingKey::LocalStatic))?;
                let re =
                    self.keys.re.as_ref().ok_or({
                        NoiseError::MissingRequirements(MissingKey::RemoteEphemeral)
                    })?;

                D::dh(s.private(), re)
            } else {
                let e =
                    self.keys.e.as_ref().ok_or({
                        NoiseError::MissingRequirements(MissingKey::LocalEphemeral)
                    })?;
                let rs = self
                    .keys
                    .rs
                    .as_ref()
                    .ok_or(NoiseError::MissingRequirements(MissingKey::RemoteStatic))?;

                D::dh(e.private(), rs)
            };

        self.s_state.mix_key::<D>(dh_res.as_ref());
        Ok(())
    }

    /// Performs the `ss` DH token: mixes `DH(local_static,
    /// remote_static)` into the symmetric state's chaining key.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError::MissingRequirements`] if either static key
    /// is missing.
    fn mix_ss(&mut self) -> Result<(), NoiseError> {
        let s = self
            .keys
            .s
            .as_ref()
            .ok_or(NoiseError::MissingRequirements(MissingKey::LocalStatic))?;
        let rs = self
            .keys
            .rs
            .as_ref()
            .ok_or(NoiseError::MissingRequirements(MissingKey::RemoteStatic))?;

        self.s_state.mix_key::<D>(D::dh(s.private(), rs).as_ref());
        Ok(())
    }

    /// Performs the `psk` token: mixes the pre-shared key into both
    /// the chaining key and the handshake hash.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError::MissingRequirements`] if no PSK was
    /// supplied.
    fn mix_psk(&mut self) -> Result<(), NoiseError> {
        let psk = self
            .keys
            .psk
            .as_ref()
            .ok_or(NoiseError::MissingRequirements(MissingKey::Psk))?;

        self.s_state.mix_key_and_hash::<D>(psk.as_bytes());

        Ok(())
    }

    /// Writes the next handshake message into `message_buffer`,
    /// encrypting `payload` as the message's payload.
    /// 
    /// # Errors
    ///
    /// Returns [`NoiseError::HandshakeFinished`] if all messages for
    /// this pattern have already been written,
    /// [`NoiseError::MissingRequirements`] if a required key is
    /// missing, [`NoiseError::InvalidState`] if `self.e` is unexpectedly
    /// already set or `message_buffer` is too small, or
    /// [`NoiseError::InvalidInput`] if the resulting message would
    /// exceed [`MAX_MESSAGE_LEN`].
    /// 
    /// # Returns
    /// 
    /// [`HandshakeResult::Continue`] if more messages remain, or
    /// [`HandshakeResult::Complete`]
    pub fn write_message<Rng: Random + CryptoRng>(
        &mut self,
        payload: &[u8],
        message_buffer: &mut [u8],
        rng: &mut Rng,
    ) -> Result<HandshakeResult<C, D, R>, NoiseError> {
        debug!(
            "[write_message] step {} for initiator ? {}",
            self.step,
            R::IS_INITIATOR
        );

        let messages = P::HANDSHAKE.messages();

        if self.step >= messages.len() {
            return Err(NoiseError::HandshakeFinished);
        }

        let mut buf_index = 0;
        let next_message = &messages[self.step];

        for token in next_message.tokens {
            match token {
                Token::E => {
                    if self.e_set {
                        return Err(NoiseError::InvalidState("e must be empty"));
                    }

                    let e: D::Keypair = match self.keys.e.take() {
                        Some(e) => e,
                        None => D::generate_keypair(rng),
                    };

                    let pk_bytes = e.pubkey_bytes();

                    let end = checked_message_end(buf_index, pk_bytes.len())?;

                    if message_buffer.len() < end {
                        return Err(NoiseError::InvalidInput("Truncated message"));
                    }

                    self.keys.e = Some(e);
                    self.e_set = true;

                    if message_buffer.len() < buf_index + pk_bytes.len() {
                        return Err(NoiseError::InvalidInput("Truncated message"));
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
                        .ok_or(NoiseError::MissingRequirements(MissingKey::LocalStatic))?
                        .pubkey_bytes();

                    let s_len = pk_bytes
                        .len()
                        .checked_add(TAG_LEN)
                        .ok_or(NoiseError::InvalidInput("Overflow during S pattern."))?;

                    let end = checked_message_end(buf_index, s_len)?;
                    if message_buffer.len() < end
                        || pk_bytes.len() + TAG_LEN > message_buffer.len() - buf_index
                    {
                        return Err(NoiseError::InvalidState("Message buffer is full"));
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
                Token::PSK => self.mix_psk()?,
            }
        }

        self.step += 1;

        if payload.len() > message_buffer.len() - buf_index {
            return Err(NoiseError::InvalidState("No place left for the payload"));
        }

        let payload_ct_len = self
            .s_state
            .encrypt_and_hash(payload, &mut message_buffer[buf_index..])?;

        let end = checked_message_end(buf_index, payload_ct_len)?;
        if message_buffer.len() < end {
            return Err(NoiseError::InvalidInput(
                "Message is bigger than the maximum allowed",
            ));
        }

        buf_index = end;

        if self.step == messages.len() {
            let (c1, c2) = self.s_state.split::<D>();
            let remote_pk = self.keys.rs.take();

            // To zeroize the keys
            self.keys.clear();
            
            let transport_state = TransportState::new(c1, c2, remote_pk);
            Ok(HandshakeResult::Complete {
                bytes_written: buf_index,
                transport_state,
                handshake_hash: self.s_state.get_handshake_hash()?,
            })
        } else {
            Ok(HandshakeResult::Continue { bytes: buf_index })
        }
    }

    /// Reads and processes the next handshake message from `message`,
    /// decrypting its payload into `payload_buffer`.
    /// 
    /// # Errors
    ///
    /// Returns [`NoiseError::InvalidInput`] if `message` exceeds
    /// [`MAX_MESSAGE_LEN`], [`NoiseError::HandshakeFinished`] if all
    /// messages have already been read, or
    /// [`NoiseError::InvalidState`]/decryption errors if `message` is
    /// malformed, truncated, or fails authentication.
    ///
    /// # Returns
    ///
    /// [`HandshakeResult::Continue`] if more messages remain, or
    /// [`HandshakeResult::Complete`]
    pub fn read_message(
        &mut self,
        message: &[u8],
        payload_buffer: &mut [u8],
    ) -> Result<HandshakeResult<C, D, R>, NoiseError> {
        if message.len() > MAX_MESSAGE_LEN {
            return Err(NoiseError::InvalidInput("Message received too big"));
        }
        debug!(
            "[read_message] step {} for initiator ? {}",
            self.step,
            R::IS_INITIATOR
        );
        let messages = P::HANDSHAKE.messages();

        if self.step >= messages.len() {
            return Err(NoiseError::HandshakeFinished);
        }

        let mut buf_index = 0;
        let next_message = &messages[self.step];

        for token in next_message.tokens {
            match token {
                Token::E => {
                    if self.keys.re.is_some() {
                        return Err(NoiseError::InvalidState("re must be empty"));
                    }

                    if message.len() < buf_index + D::DHLEN {
                        return Err(NoiseError::InvalidState("Truncated message for e"));
                    }

                    let re_bytes = &message[buf_index..buf_index + D::DHLEN];
                    buf_index += D::DHLEN;

                    let re = D::pubkey_from_bytes(re_bytes)?;
                    self.keys.re = Some(re);

                    self.s_state.mix_hash(re_bytes);

                    if P::HANDSHAKE.has_psk() {
                        self.s_state.mix_key::<D>(re_bytes);
                    }
                }
                Token::S => {
                    let len = if self.s_state.has_key() {
                        D::DHLEN + 16
                    } else {
                        D::DHLEN
                    };

                    if message.len() < buf_index + len {
                        return Err(NoiseError::InvalidState("Truncated message for e"));
                    }

                    let temp = &message[buf_index..buf_index + len];
                    trace!("Encrypted rs when reading: {:?}", &temp);

                    buf_index += len;

                    let mut rs = vec![0u8; D::DHLEN + TAG_LEN];
                    self.s_state.decrypt_and_hash(temp, &mut rs)?;

                    self.keys.rs = Some(D::pubkey_from_bytes(&rs[..D::DHLEN])?);
                }
                Token::EE => self.mix_ee()?,
                Token::ES => self.mix_es()?,
                Token::SE => self.mix_se()?,
                Token::SS => self.mix_ss()?,
                Token::PSK => self.mix_psk()?,
            }
        }

        self.step += 1;

        trace!("Message len: {}, buf_index: {}", message.len(), buf_index);
        self.s_state
            .decrypt_and_hash(&message[buf_index..], payload_buffer)?;

        if self.step == messages.len() {
            let (c1, c2) = self.s_state.split::<D>();
            let remote_pk = self.keys.rs.take();

            // To zeroize the keys
            self.keys.clear();

            let transport_state = TransportState::new(c1, c2, remote_pk);
            Ok(HandshakeResult::Complete {
                bytes_written: message.len(),
                transport_state,
                handshake_hash: self.s_state.get_handshake_hash()?,
            })
        } else {
            Ok(HandshakeResult::Continue { bytes: buf_index })
        }
    }
}
