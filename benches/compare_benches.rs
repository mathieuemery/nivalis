#![allow(clippy::shadow_reuse)]
#[macro_use]
extern crate criterion;

use criterion::{Criterion, Throughput};
use snow::{params::NoiseParams, Builder};
use nivalis::{
    builder::NewBuilder,
    crypto::{
        cipher::chacha20::ChaChaPoly,
        dh::{DH, DHKeypair, x25519::X25519dh},
        hash::{blake2b::Blake2b, blake2s::Blake2s, sha256::Sha256},
    },
    patterns::{NN, XX, roles::{Initiator, Responder}},
    state::handshake_state::HandshakeResult,
};
use rand::rng;

const MSG_SIZE: usize = 4096;

fn bench_builder(c: &mut Criterion) {
    let mut builder_group = c.benchmark_group("snow_builder");
    builder_group.throughput(Throughput::Elements(1));
    builder_group.bench_function("snow_skeleton", |b| {
        b.iter(move || {
            Builder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap())
                .build_initiator()
                .unwrap();
        });
    });

    builder_group.bench_function("nivalis_skeleton", |b| {
        b.iter( || {
            NewBuilder::<NN, Initiator, X25519dh, ChaChaPoly, Sha256>::new()
                .build()
                .unwrap()
        });
    });

    builder_group.bench_function("snow_withkey", |b| {
        b.iter(move || {
            Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
                .local_private_key(&[1_u8; 32])
                .unwrap()
                .build_initiator()
                .unwrap();
        });
    });

    builder_group.bench_function("nivalis_withkey", |b| {
        let keys = X25519dh::generate_keypair(&mut rng());
        b.iter( || {
            NewBuilder::<XX, Initiator, X25519dh, ChaChaPoly, Sha256>::new()
                .local_static_key(keys.private().clone())
                .build()
                .unwrap()
        });
    });

    builder_group.finish();
}

fn bench_handshake(c: &mut Criterion) {
    let mut rng = rng();
    let mut handshake_group = c.benchmark_group("snow_handshake");
    handshake_group.throughput(Throughput::Elements(1));
    handshake_group.bench_function("snow_xx", |b| {
        b.iter( || {
            let pattern: NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2b".parse().unwrap();
            let mut h_i = Builder::new(pattern.clone())
                .local_private_key(&[1_u8; 32])
                .unwrap()
                .build_initiator()
                .unwrap();
            let mut h_r = Builder::new(pattern)
                .local_private_key(&[2_u8; 32])
                .unwrap()
                .build_responder()
                .unwrap();

            let mut buffer_msg = [0_u8; MSG_SIZE * 2];
            let mut buffer_out = [0_u8; MSG_SIZE * 2];

            // get the handshaking out of the way for even testing
            let len = h_i.write_message(&[0_u8; 0], &mut buffer_msg).unwrap();
            h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
            let len = h_r.write_message(&[0_u8; 0], &mut buffer_msg).unwrap();
            h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
            let len = h_i.write_message(&[0_u8; 0], &mut buffer_msg).unwrap();
            h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
        });
    });

    handshake_group.bench_function("nivalis_xx", |b| {
        let init = X25519dh::generate_keypair(&mut rng);
        let resp = X25519dh::generate_keypair(&mut rng);
        b.iter( || {
            let mut h_i = NewBuilder::<XX, Initiator, X25519dh, ChaChaPoly, Blake2b>::new()
                .local_static_key(init.private().clone())
                .build()
                .unwrap();

            let mut h_r = NewBuilder::<XX, Responder, X25519dh, ChaChaPoly, Blake2b>::new()
                .local_static_key(resp.private().clone())
                .build()
                .unwrap();

            let mut buffer_msg = [0_u8; MSG_SIZE * 2];
            let mut buffer_out = [0_u8; MSG_SIZE * 2];

            // get the handshaking out of the way for even testing
            let len = match h_i.write_message(&[0_u8; 0], &mut buffer_msg, &mut rng).unwrap() {
                HandshakeResult::Continue { bytes } => bytes,
                HandshakeResult::Complete { .. } => panic!("responder shouldn't finish at message 1"),
            };
            h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

            let len = match h_r.write_message(&[0_u8; 0], &mut buffer_msg, &mut rng).unwrap(){
                HandshakeResult::Continue { bytes } => bytes,
                HandshakeResult::Complete { .. } => panic!("responder shouldn't finish at message 2"),
            };
            h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

            let (len, _) = match h_i.write_message(&[0_u8; 0], &mut buffer_msg, &mut rng).unwrap(){
                HandshakeResult::Continue { .. } => panic!("expected initiator to complete at message 3"),
                HandshakeResult::Complete { bytes_written, transport_state, .. } => {
                    (bytes_written, transport_state)
                }
            };
            h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
        });
    });

    handshake_group.bench_function("snow_nn", |b| {
        b.iter( || {
            let pattern = "Noise_NN_25519_ChaChaPoly_BLAKE2b";
            let mut h_i = Builder::new(pattern.parse().unwrap()).build_initiator().unwrap();
            let mut h_r = Builder::new(pattern.parse().unwrap()).build_responder().unwrap();

            let mut buffer_msg = [0_u8; MSG_SIZE * 2];
            let mut buffer_out = [0_u8; MSG_SIZE * 2];

            // get the handshaking out of the way for even testing
            let len = h_i.write_message(&[0_u8; 0], &mut buffer_msg).unwrap();
            h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
            let len = h_r.write_message(&[0_u8; 0], &mut buffer_msg).unwrap();
            h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
        });
    });

    handshake_group.bench_function("nivalis_nn", |b| {
        b.iter( || {
            let mut h_i = NewBuilder::<NN, Initiator, X25519dh, ChaChaPoly, Blake2b>::new()
                .build()
                .unwrap();

            let mut h_r = NewBuilder::<NN, Responder, X25519dh, ChaChaPoly, Blake2b>::new()
                .build()
                .unwrap();

            let mut buffer_msg = [0_u8; MSG_SIZE * 2];
            let mut buffer_out = [0_u8; MSG_SIZE * 2];

            // get the handshaking out of the way for even testing
            let len = match h_i.write_message(&[0_u8; 0], &mut buffer_msg, &mut rng).unwrap() {
                HandshakeResult::Continue { bytes } => bytes,
                HandshakeResult::Complete { .. } => panic!("responder shouldn't finish at message 1"),
            };
            h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

            let (len, _) = match h_r.write_message(&[0_u8; 0], &mut buffer_msg, &mut rng).unwrap(){
                HandshakeResult::Continue { .. } => panic!("expected initiator to complete at message 2"),
                HandshakeResult::Complete { bytes_written,  transport_state, .. } => {
                    (bytes_written, transport_state)
                }
            };
            h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
        });
    });

    handshake_group.finish();
}

fn bench_transport(c: &mut Criterion) {
    let mut rng = rng();

    let mut transport_group = c.benchmark_group("snow_transport");
    transport_group.throughput(Throughput::Bytes(u64::try_from(MSG_SIZE * 2).unwrap()));

    transport_group.bench_function("Snow ChaChaPoly_BLAKE2s throughput", |b| {
        static PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

        let mut h_i = Builder::new(PATTERN.parse().unwrap()).build_initiator().unwrap();
        let mut h_r = Builder::new(PATTERN.parse().unwrap()).build_responder().unwrap();

        let mut buffer_msg = [0_u8; MSG_SIZE * 2];
        let mut buffer_out = [0_u8; MSG_SIZE * 2];

        // get the handshaking out of the way for even testing
        let len = h_i.write_message(&[0_u8; 0], &mut buffer_msg).unwrap();
        h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
        let len = h_r.write_message(&[0_u8; 0], &mut buffer_msg).unwrap();
        h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

        let mut h_i = h_i.into_transport_mode().unwrap();
        let mut h_r = h_r.into_transport_mode().unwrap();

        b.iter(move || {
            let len = h_i.write_message(&buffer_msg[..MSG_SIZE], &mut buffer_out).unwrap();
            let _ = h_r.read_message(&buffer_out[..len], &mut buffer_msg).unwrap();
        });
    });

    transport_group.bench_function("Nivalis ChaChaPoly_BLAKE2s throughput", |b| {
        let mut h_i = NewBuilder::<NN, Initiator, X25519dh, ChaChaPoly, Blake2s>::new()
                .build()
                .unwrap();

        let mut h_r = NewBuilder::<NN, Responder, X25519dh, ChaChaPoly, Blake2s>::new()
            .build()
            .unwrap();

        let mut buffer_msg = [0_u8; MSG_SIZE * 2];
        let mut buffer_out = [0_u8; MSG_SIZE * 2];

        // get the handshaking out of the way for even testing
        let len = match h_i.write_message(&[0_u8; 0], &mut buffer_msg, &mut rng).unwrap() {
            HandshakeResult::Continue { bytes } => bytes,
            HandshakeResult::Complete { .. } => panic!("responder shouldn't finish at message 1"),
        };
        h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

        let (len, mut resp_ts) = match h_r.write_message(&[0_u8; 0], &mut buffer_msg, &mut rng).unwrap(){
            HandshakeResult::Continue { .. } => panic!("expected initiator to complete at message 2"),
            HandshakeResult::Complete { bytes_written, transport_state, .. } => {
                (bytes_written, transport_state)
            }
        };
        let (_, mut init_ts) = match h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap(){
            HandshakeResult::Continue { .. } => panic!("expected responder to complete at message 2"),
            HandshakeResult::Complete { bytes_written, transport_state, .. } => {
                (bytes_written, transport_state)
            }
        };

        b.iter(move || {
            let len = init_ts.encrypt_message(&[], &buffer_msg[..MSG_SIZE], &mut buffer_out).unwrap();
            resp_ts.decrypt_message(&[], &buffer_out[..len], &mut buffer_msg).unwrap();
        });
    });
}

criterion_group!(benches, bench_builder, bench_handshake, bench_transport);
criterion_main!(benches);