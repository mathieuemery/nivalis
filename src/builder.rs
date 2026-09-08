//! Typestate builder for the Noise handshake

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::crypto::{
    cipher::Cipher,
    dh::{DH, DHKeypair},
    hash::Hash,
};
use crate::error::{MissingKey, NoiseError};
use crate::patterns::roles::*;
use crate::state::handshake_state::{HandshakeKeys, HandshakeState};
use crate::types::Psk;

/// A compile-time checked builder for assembling the keys and parameters
/// needed to start a Noise handshake.
/// 
/// Uses const generic flags (`LS`, `RS`, `LE`, `RE`, `PSK`) to track
/// which keys have been provided.
/// 
/// Each call to the `.local_static_key(...)`, `.remote_static_key(...)`, etc.
/// setters consume `self` and returns a builder with the corresponding flags
/// flipped to `true`.
/// 
/// Makes it impossible for the user to call `.build()` twice or forget a key
/// required by the chosen pattern.
/// 
/// Uses const `assert!` in the the `.build()` method to block the compilation
/// of an invalid state and provide a proper error message.
/// 
/// # Type parameters
/// - `P`: the Noise pattern (ex: `NN`, `XX`, `IKpsk2`) which determines which
/// keys are required before calling `.build()`.
/// - `R`: the role in the handshake ([`Initiator`] or [`Responder`]).
/// - `D`: the DH function (ex: X25519)
/// - `C`: the AEAD cipher (ex: ChaCha20-Poly1305)
/// - `H`: the hash function (ex: BLAKE2s)
/// 
/// # Const generic parameters
/// - `LS`, `RS`, `LE`, `RE`, `PSK`: whether the local/remote static/ephemeral
/// or PSK keys have been provided.
/// 
/// # Example
/// ```rust
/// let initiator = NewBuilder::<IK, Initiator, X25519dh, ChaChaPoly, Blake2s>::new()
///     .local_static_key(init_static.private().clone()
///     .remote_static_key(resp_static.public())
///     .build()?;
/// ```
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

/// A newly created [`HandshakeParamsBuilder`] with no keys set yet.
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
    /// Creates a new empty handshake builder with no keys or prologue yet.
    /// 
    /// Use the `.local_static_key(...)`, `.remote_static_key(...)`,
    /// `.psk(...)`, etc. later to provide the required keys and then call
    /// `.build()` to get a [`HandshakeState`]
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

    /// Builds a [`HandshakeState`] directly from key material,
    /// bypasses the typestate builder.
    /// 
    /// This exists primarily for integration tests where keys
    /// are assembled dynamically from test vectors. Prefer the typestate
    /// builder (`NewBuilder::new`) in normal application code.
    /// 
    /// # Errors
    /// Returns [`NoiseError::MissingRequirements`] if a key required by
    /// the pattern wasn't provided
    pub fn from_parts(
        local_static: Option<D::PrivKey>,
        remote_static: Option<D::PubKey>,
        local_ephemeral: Option<D::PrivKey>,
        remote_ephemeral: Option<D::PubKey>,
        psk: Option<Psk>,
        prologue: Vec<u8>,
    ) -> Result<HandshakeState<P, R, D, C, H>, NoiseError> {
        if P::LOCAL_STATIC_REQUIRED && local_static.is_none() {
            return Err(NoiseError::MissingRequirements(MissingKey::LocalStatic));
        }
        if P::REMOTE_STATIC_REQUIRED && remote_static.is_none() {
            return Err(NoiseError::MissingRequirements(MissingKey::RemoteStatic));
        }
        if P::LOCAL_EPHEMERAL_REQUIRED && local_ephemeral.is_none() {
            return Err(NoiseError::MissingRequirements(MissingKey::LocalEphemeral));
        }
        if P::REMOTE_EPHEMERAL_REQUIRED && remote_ephemeral.is_none() {
            return Err(NoiseError::MissingRequirements(MissingKey::RemoteEphemeral));
        }
        if P::PSK_REQUIRED && psk.is_none() {
            return Err(NoiseError::MissingRequirements(MissingKey::Psk));
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
    /// Sets the local static private key and derive the corresponding keypair.
    /// 
    /// Only available when the local static key hasn't been provided yet
    /// (`LS = false`). Calling this multiple times creates a compilation error.
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
    /// Sets the remote party's static public key.
    /// 
    /// Required by patterns where the remote's static key is known in advance
    /// (ex: `IK`, `XK`). Only available when not set (`RS = true`).
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
    /// Sets the local ephermeral private key and derive the corresponding keypair.
    /// 
    /// Normally never used outside of tests as the ephemeral key is created during
    /// the handshake. Only available when not set (`LE = false`)
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
    /// Sets the remote's ephemeral public key.
    /// 
    /// Required as a pre-message on patterns/role where the peer's ephemeral key
    /// is known in advance (see Section 7). Only available when not set (`RE = false`)
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

impl<P, R, D, C, H, const LS: bool, const RS: bool, const LE: bool, const RE: bool>
    HandshakeParamsBuilder<P, R, D, C, H, LS, RS, LE, RE, false>
where
    P: PatternRequirements<R>,
    R: RoleMarker,
    D: DH,
    C: Cipher,
    H: Hash,
{
    /// Sets the Pre-Shared Key that will be mixed in the handshake.
    /// 
    /// You don't define the position of the PSK here, it will automatically be used
    /// where the pattern defines it. Only available when not set (`PSK = false`)
    pub fn psk(self, psk: [u8; 32]) -> HandshakeParamsBuilder<P, R, D, C, H, LS, RS, LE, RE, true> {
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
    /// Sets the optional prologue data mixed into the handshake hash.
    /// 
    /// The prologue can be used by any pattern and both parties must agree on it
    /// beforehand. Defaults to empty if not set.
    pub fn prologue(mut self, prologue: Vec<u8>) -> Self {
        self.prologue = prologue;
        self
    }

    /// Validates the builder's state and initializes a [`HandshakeState`].
    /// 
    /// # Errors
    /// 
    /// Returns a [`NoiseError`] if handshake initialization fails or
    /// if required keys where not provided.
    pub fn build(self) -> Result<HandshakeState<P, R, D, C, H>, NoiseError> {
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
