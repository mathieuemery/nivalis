use nivalis::{
    builder::NewBuilder,
    crypto::{
        cipher::chacha20::ChaChaPoly,
        dh::{
            DH, DHKeypair,
            x25519::{X25519Keys, X25519dh},
        },
        hash::blake2s::Blake2s,
    },
    patterns::{
        XX,
        roles::{Initiator, Responder},
    },
    state::{
        cipher_state::CipherState,
        handshake_state::{HandshakeResult, HandshakeState},
    },
};

/// Only used to simplify the usage
type HsInit = HandshakeState<XX, Initiator, X25519dh, ChaChaPoly, Blake2s>;
type HsResp = HandshakeState<XX, Responder, X25519dh, ChaChaPoly, Blake2s>;
type Ct = CipherState<ChaChaPoly>;

const MAX_HANDSHAKE_MSG: usize = 256;

fn build_initiator(init: &X25519Keys) -> HsInit {
    NewBuilder::<XX, Initiator, X25519dh, ChaChaPoly, Blake2s>::new()
        .local_static_key(init.private().clone())
        .build()
        .expect("failed to build initiator handshake state")
}

fn build_responder(resp: &X25519Keys) -> HsResp {
    NewBuilder::<XX, Responder, X25519dh, ChaChaPoly, Blake2s>::new()
        .local_static_key(resp.private().clone())
        .build()
        .expect("failed to build responder handshake state")
}

fn full_handshake(init_hs: &mut HsInit, resp_hs: &mut HsResp) -> ((Ct, Ct), (Ct, Ct)) {
    let mut wire = [0u8; MAX_HANDSHAKE_MSG];
    let mut buf = [0u8; MAX_HANDSHAKE_MSG];

    // Message 1: e
    let len = match init_hs
        .write_message(b"", &mut wire)
        .expect("write msg 1")
    {
        HandshakeResult::Continue { bytes } => bytes,
        HandshakeResult::Complete { .. } => {
            panic!("Initiator shouldn't have finished at message 1")
        }
    };

    resp_hs
        .read_message(&wire[..len], &mut buf)
        .expect("read msg 1");

    // Message 2: e, ee, s, es
    let len = match resp_hs
        .write_message(b"", &mut wire)
        .expect("write msg 2")
    {
        HandshakeResult::Continue { bytes } => bytes,
        HandshakeResult::Complete { .. } => {
            panic!("Responder shouldn't have finished at message 2")
        }
    };

    init_hs
        .read_message(&wire[..len], &mut buf)
        .expect("read msg 2");

    // Message 3: s, se
    let (len, init_split) = match init_hs
        .write_message(b"", &mut wire)
        .expect("write msg 3")
    {
        HandshakeResult::Continue { .. } => {
            panic!("expected initiator to complete at message 3")
        }
        HandshakeResult::Complete {
            bytes_written,
            initiator,
            responder,
            ..
        } => (bytes_written, (initiator, responder)),
    };

    let resp_split = match resp_hs
        .read_message(&wire[..len], &mut buf)
        .expect("read msg 3")
    {
        HandshakeResult::Continue { .. } => {
            panic!("expected responder to complete at message 3")
        }
        HandshakeResult::Complete {
            initiator,
            responder,
            ..
        } => (initiator, responder),
    };


    (init_split, resp_split)
}

fn round_trip(init_send: &mut Ct, resp_recv: &mut Ct, resp_send: &mut Ct, init_recv: &mut Ct) {
    // Send a message from initiator to responder
    let plaintext = b"hello from initiator";
    let mut ct = vec![0u8; plaintext.len() + 32];
    let ct_len = init_send
        .encrypt_with_ad(b"", plaintext, &mut ct)
        .expect("encrypt failed");

    let mut recovered = vec![0u8; plaintext.len()];
    resp_recv
        .decrypt_with_ad(b"", &ct[..ct_len], &mut recovered)
        .expect("decrypt failed");

    assert_eq!(&recovered, plaintext);
    println!(
        "Responder decrypted: {:?}",
        String::from_utf8_lossy(&recovered)
    );

    // Send from responder to initiator
    let reply = b"hello from responder";
    let mut ct2 = vec![0u8; reply.len() + 32];
    let ct2_len = resp_send
        .encrypt_with_ad(b"", reply, &mut ct2)
        .expect("encrypt failed");

    let mut recovered2 = vec![0u8; reply.len()];
    init_recv
        .decrypt_with_ad(b"", &ct2[..ct2_len], &mut recovered2)
        .expect("decrypt failed");

    assert_eq!(&recovered2, reply);
    println!(
        "Initiator decrypted: {:?}",
        String::from_utf8_lossy(&recovered2)
    );
}

fn main() {
    let init_static = X25519dh::generate_keypair();
    let resp_static = X25519dh::generate_keypair();

    let mut init_hs = build_initiator(&init_static);
    let mut resp_hs = build_responder(&resp_static);

    let ((mut init_send, mut init_recv), (mut resp_recv, mut resp_send)) =
        full_handshake(&mut init_hs, &mut resp_hs);

    println!("Handshake complete.");

    round_trip(
        &mut init_send,
        &mut resp_recv,
        &mut resp_send,
        &mut init_recv,
    );

    println!("Round-trip OK");
}
