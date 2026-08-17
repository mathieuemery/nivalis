//! Roles of the handshake (initiator or responder)

use crate::patterns::*;

pub trait RoleMarker: Copy + 'static {
    const IS_INITIATOR: bool;
}

#[derive(Copy, Clone)]
pub struct Initiator;
#[derive(Copy, Clone)]
pub struct Responder;

impl RoleMarker for Initiator {
    const IS_INITIATOR: bool = true;
}
impl RoleMarker for Responder {
    const IS_INITIATOR: bool = false;
}

/// For a given Pattern + Role, which builder fields are mandatory.
pub trait PatternRequirements<R: RoleMarker>: Pattern {
    const LOCAL_STATIC_REQUIRED: bool;
    const REMOTE_STATIC_REQUIRED: bool;
    const LOCAL_EPHEMERAL_REQUIRED: bool;
    const REMOTE_EPHEMERAL_REQUIRED: bool;
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
