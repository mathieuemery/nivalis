//! Remote keys that are not pre-messages of the pattern are rejected.
//!
//! The typestate builder rejects them at compile time (see the `compile_fail`
//! doctests on `remote_static_key` / `remote_ephemeral_key`); `from_parts`
//! rejects them at run time.

use nivalis::{
    builder::NewBuilder,
    crypto::{
        cipher::chacha20::ChaChaPoly,
        dh::{DH, DHKeypair, x25519::X25519dh},
        hash::blake2s::Blake2s,
    },
    error::NoiseError,
    patterns::{
        IK, NN, XX,
        roles::{Initiator, Responder},
    },
};
use rand::rng;

#[test]
fn from_parts_rejects_unexpected_remote_static() {
    let mut r = rng();
    let peer = X25519dh::generate_keypair(&mut r);

    // NN: the initiator never sends its static key, so a key passed here would
    // otherwise end up in `TransportState::remote_static_pk()` unauthenticated.
    let res = NewBuilder::<NN, Responder, X25519dh, ChaChaPoly, Blake2s>::from_parts(
        None, Some(peer.public()), None, None, None, vec![],
    );
    assert!(matches!(res, Err(NoiseError::InvalidInput(_))));

    // XX: the responder sends its static key, which would silently replace this one.
    let me = X25519dh::generate_keypair(&mut r);
    let res = NewBuilder::<XX, Initiator, X25519dh, ChaChaPoly, Blake2s>::from_parts(
        Some(me.private().to_owned()), Some(peer.public()), None, None, None, vec![],
    );
    assert!(matches!(res, Err(NoiseError::InvalidInput(_))));
}

#[test]
fn from_parts_rejects_unexpected_remote_ephemeral() {
    let mut r = rng();
    let peer = X25519dh::generate_keypair(&mut r);
    let res = NewBuilder::<NN, Initiator, X25519dh, ChaChaPoly, Blake2s>::from_parts(
        None, None, None, Some(peer.public()), None, vec![],
    );
    assert!(matches!(res, Err(NoiseError::InvalidInput(_))));
}

#[test]
fn from_parts_accepts_premessage_remote_static() {
    let mut r = rng();
    let me = X25519dh::generate_keypair(&mut r);
    let peer = X25519dh::generate_keypair(&mut r);
    let res = NewBuilder::<IK, Initiator, X25519dh, ChaChaPoly, Blake2s>::from_parts(
        Some(me.private().to_owned()), Some(peer.public()), None, None, None, vec![],
    );
    assert!(res.is_ok());
}
