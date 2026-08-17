//! Typestate builder for the Noise handshake

use std::marker::PhantomData;

use anyhow::{Result, bail};

use crate::crypto::dh::DHKeypair;
use crate::crypto::{cipher::Cipher, dh::DH, hash::Hash};
use crate::patterns::roles::*;
use crate::state::handshake_state::{HandshakeKeys, HandshakeState};
use crate::types::Psk;

pub struct HandshakeParamsBuilder<
    P,
    R,
    D,
    C,
    H,
    const LS: bool,
    const RS: bool,
    const LE: bool,
    const RE: bool,
    const PSK: bool,
> where
    P: PatternRequirements<R>,
    R: RoleMarker,
    D: DH,
    C: Cipher,
    H: Hash,
{
    local_static: Option<D::Keypair>,
    remote_static: Option<D::PubKey>,
    local_ephemeral: Option<D::Keypair>,
    remote_ephemeral: Option<D::PubKey>,
    psk: Option<Psk>,
    prologue: Vec<u8>,
    _marker: PhantomData<(P, R, C, H)>,
}

pub type NewBuilder<P, R, D, C, H> =
    HandshakeParamsBuilder<P, R, D, C, H, false, false, false, false, false>;

impl<P, R, D, C, H> NewBuilder<P, R, D, C, H>
where
    P: PatternRequirements<R>,
    R: RoleMarker,
    D: DH,
    C: Cipher,
    H: Hash,
{
    pub fn new() -> Self {
        HandshakeParamsBuilder {
            local_static: None,
            remote_static: None,
            local_ephemeral: None,
            remote_ephemeral: None,
            psk: None,
            prologue: Vec::new(),
            _marker: PhantomData,
        }
    }

    pub fn from_parts(
        local_static: Option<D::PrivKey>,
        remote_static: Option<D::PubKey>,
        local_ephemeral: Option<D::PrivKey>,
        remote_ephemeral: Option<D::PubKey>,
        psk: Option<Psk>,
        prologue: Vec<u8>,
    ) -> Result<HandshakeState<P, R, D, C, H>> {
        if P::LOCAL_STATIC_REQUIRED && local_static.is_none() {
            bail!("missing local_static: this pattern/role requires a local static key",);
        }
        if P::REMOTE_STATIC_REQUIRED && remote_static.is_none() {
            bail!(
                "missing remote_static: the peer's static key is a pre-message for this pattern/role"
            );
        }
        if P::LOCAL_EPHEMERAL_REQUIRED && local_ephemeral.is_none() {
            bail!(
                "missing local_ephemeral: this role sends a message and needs its own ephemeral key"
            );
        }
        if P::REMOTE_EPHEMERAL_REQUIRED && remote_ephemeral.is_none() {
            bail!(
                "missing remote_ephemeral: the peer's ephemeral key is a pre-message for this pattern/role"
            );
        }
        if P::PSK_REQUIRED && psk.is_none() {
            bail!("missing psk: this pattern requires at least one pre-shared key");
        }

        let s: Option<D::Keypair> = match local_static {
            Some(s) => Some(D::Keypair::derive_keypair(&s)),
            None => None,
        };

        let e: Option<D::Keypair> = match local_ephemeral {
            Some(e) => Some(D::Keypair::derive_keypair(&e)),
            None => None,
        };

        let keys = HandshakeKeys {
            s,
            e,
            rs: remote_static,
            re: remote_ephemeral,
            psk,
        };

        HandshakeState::initialize(&prologue, keys)
    }
}

impl<P, R, D, C, H> Default for NewBuilder<P, R, D, C, H>
where
    P: PatternRequirements<R>,
    R: RoleMarker,
    D: DH,
    C: Cipher,
    H: Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<P, R, D, C, H, const RS: bool, const LE: bool, const RE: bool, const PSK: bool>
    HandshakeParamsBuilder<P, R, D, C, H, false, RS, LE, RE, PSK>
where
    P: PatternRequirements<R>,
    R: RoleMarker,
    D: DH,
    C: Cipher,
    H: Hash,
{
    pub fn local_static_key(
        self,
        sk: D::PrivKey,
    ) -> HandshakeParamsBuilder<P, R, D, C, H, true, RS, LE, RE, PSK> {
        let kp = D::Keypair::derive_keypair(&sk);
        HandshakeParamsBuilder {
            local_static: Some(kp),
            remote_static: self.remote_static,
            local_ephemeral: self.local_ephemeral,
            remote_ephemeral: self.remote_ephemeral,
            psk: self.psk,
            prologue: self.prologue,
            _marker: PhantomData,
        }
    }
}

impl<P, R, D, C, H, const LS: bool, const LE: bool, const RE: bool, const PSK: bool>
    HandshakeParamsBuilder<P, R, D, C, H, LS, false, LE, RE, PSK>
where
    P: PatternRequirements<R>,
    R: RoleMarker,
    D: DH,
    C: Cipher,
    H: Hash,
{
    pub fn remote_static_key(
        self,
        pk: D::PubKey,
    ) -> HandshakeParamsBuilder<P, R, D, C, H, LS, true, LE, RE, PSK> {
        HandshakeParamsBuilder {
            local_static: self.local_static,
            remote_static: Some(pk),
            local_ephemeral: self.local_ephemeral,
            remote_ephemeral: self.remote_ephemeral,
            psk: self.psk,
            prologue: self.prologue,
            _marker: PhantomData,
        }
    }
}

impl<P, R, D, C, H, const LS: bool, const RS: bool, const RE: bool, const PSK: bool>
    HandshakeParamsBuilder<P, R, D, C, H, LS, RS, false, RE, PSK>
where
    P: PatternRequirements<R>,
    R: RoleMarker,
    D: DH,
    C: Cipher,
    H: Hash,
{
    pub fn local_ephemeral_key(
        self,
        sk: D::PrivKey,
    ) -> HandshakeParamsBuilder<P, R, D, C, H, LS, RS, true, RE, PSK> {
        let kp = D::Keypair::derive_keypair(&sk);
        HandshakeParamsBuilder {
            local_static: self.local_static,
            remote_static: self.remote_static,
            local_ephemeral: Some(kp),
            remote_ephemeral: self.remote_ephemeral,
            psk: self.psk,
            prologue: self.prologue,
            _marker: PhantomData,
        }
    }
}

impl<P, R, D, C, H, const LS: bool, const RS: bool, const LE: bool, const PSK: bool>
    HandshakeParamsBuilder<P, R, D, C, H, LS, RS, LE, false, PSK>
where
    P: PatternRequirements<R>,
    R: RoleMarker,
    D: DH,
    C: Cipher,
    H: Hash,
{
    pub fn remote_ephemeral_key(
        self,
        pk: D::PubKey,
    ) -> HandshakeParamsBuilder<P, R, D, C, H, LS, RS, LE, true, PSK> {
        HandshakeParamsBuilder {
            local_static: self.local_static,
            remote_static: self.remote_static,
            local_ephemeral: self.local_ephemeral,
            remote_ephemeral: Some(pk),
            psk: self.psk,
            prologue: self.prologue,
            _marker: PhantomData,
        }
    }
}

impl<
    P, R, D, C, H,
    const LS: bool,
    const RS: bool,
    const LE: bool,
    const RE: bool,
>
    HandshakeParamsBuilder<P, R, D, C, H, LS, RS, LE, RE, false>
where
    P: PatternRequirements<R>,
    R: RoleMarker,
    D: DH,
    C: Cipher,
    H: Hash,
{
    pub fn psk(
        self,
        psk: [u8; 32],
    ) -> HandshakeParamsBuilder<
        P, R, D, C, H,
        LS, RS, LE, RE, true
    > {
        HandshakeParamsBuilder {
            local_static: self.local_static,
            remote_static: self.remote_static,
            local_ephemeral: self.local_ephemeral,
            remote_ephemeral: self.remote_ephemeral,
            psk: Some(psk),
            prologue: self.prologue,
            _marker: PhantomData,
        }
    }
}

impl<P, R, D, C, H, const LS: bool, const RS: bool, const LE: bool, const RE: bool, const PSK: bool>
    HandshakeParamsBuilder<P, R, D, C, H, LS, RS, LE, RE, PSK>
where
    P: PatternRequirements<R>,
    R: RoleMarker,
    D: DH,
    C: Cipher,
    H: Hash,
{
    pub fn prologue(mut self, prologue: Vec<u8>) -> Self {
        self.prologue = prologue;
        self
    }

    pub fn build(self) -> Result<HandshakeState<P, R, D, C, H>> {
        const {
            assert!(
                LS || !P::LOCAL_STATIC_REQUIRED,
                "missing `.local_static_key(...)`: this pattern/role requires a local static key before `.build()`"
            );
            assert!(
                RS || !P::REMOTE_STATIC_REQUIRED,
                "missing `.remote_static_key(...)`: the peer's static key is a pre-message for this pattern/role"
            );
            assert!(
                LE || !P::LOCAL_EPHEMERAL_REQUIRED,
                "missing `.local_ephemeral_key(...)`: this role sends a message and needs its own ephemeral key"
            );
            assert!(
                RE || !P::REMOTE_EPHEMERAL_REQUIRED,
                "missing `.remote_ephemeral_key(...)`: the peer's ephemeral key is a pre-message for this pattern/role"
            );
            assert!(
                PSK || !P::PSK_REQUIRED,
                "missing `.psk(...)`: the pattern requires a psk to be valid"
            )
        }

        let keys = HandshakeKeys {
            s: self.local_static,
            e: self.local_ephemeral,
            rs: self.remote_static,
            re: self.remote_ephemeral,
            psk: self.psk,
        };

        HandshakeState::initialize(&self.prologue, keys)
    }
}
