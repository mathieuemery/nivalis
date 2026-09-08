//! Roles of the handshake (initiator or responder)

use crate::patterns::*;

/// Marks a type as representing one of the two roles
/// in a Noise handshake: [`Initiator`] or [`Responder`].
pub trait RoleMarker: Copy + 'static {
    /// `true` if this role is the initiator
    const IS_INITIATOR: bool;
}

/// Marker type for the party that sends the first handshake message.
#[derive(Copy, Clone)]
pub struct Initiator;

/// Marker type for the party that receives the first handshake
/// message.
#[derive(Copy, Clone)]
pub struct Responder;

impl RoleMarker for Initiator {
    const IS_INITIATOR: bool = true;
}
impl RoleMarker for Responder {
    const IS_INITIATOR: bool = false;
}

/// For a given [`Pattern`] and [`RoleMarker`], determines which keys
/// are mandatory before the handshake can be built.
pub trait PatternRequirements<R: RoleMarker>: Pattern {
    /// Whether this role must supply its own local static key.
    const LOCAL_STATIC_REQUIRED: bool;
    /// Whether this role must know the peer's static key in advance
    /// rather than receiving it during the handshake.
    const REMOTE_STATIC_REQUIRED: bool;
    /// Whether this role must supply its own ephemeral static key.
    const LOCAL_EPHEMERAL_REQUIRED: bool;
    /// Whether this role must know the peer's ephemeral key in advance
    /// rather than receiving it during the handshake.
    const REMOTE_EPHEMERAL_REQUIRED: bool;
    /// Whether the pattern requires a pre-shared key.
    const PSK_REQUIRED: bool;
}

impl<P: Pattern, R: RoleMarker> PatternRequirements<R> for P {
    const LOCAL_STATIC_REQUIRED: bool = P::HANDSHAKE.local_static_required(R::IS_INITIATOR);
    const REMOTE_STATIC_REQUIRED: bool = P::HANDSHAKE.peer_static_is_premessage(R::IS_INITIATOR);
    const LOCAL_EPHEMERAL_REQUIRED: bool = P::HANDSHAKE.local_ephemeral_required(R::IS_INITIATOR);
    const REMOTE_EPHEMERAL_REQUIRED: bool =
        P::HANDSHAKE.peer_ephemeral_is_premessage(R::IS_INITIATOR);
    const PSK_REQUIRED: bool = P::HANDSHAKE.has_psk();
}
