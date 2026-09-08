//! The state objects driving the Noise handshake and transport phases:
//! [`CipherState`](cipher_state::CipherState),
//! [`SymmetricState`](symmetric_state::SymmetricState),
//! [`HandshakeState`](handshake_state::HandshakeState), and
//! [`TransportState`](transport_state::TransportState).
//! 
//! A `HandshakeState` wraps a `SymmetricState`, which in turn wraps a
//! `CipherState`. Once the handshake completes, `SymmetricState::split`
//! produces the pair of `CipherState`s that make up a `TransportState`
//! for ongoing application data encryption.

pub mod cipher_state;
pub mod handshake_state;
pub mod symmetric_state;
pub mod transport_state;