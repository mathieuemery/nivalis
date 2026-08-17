//! Testing the library with Cacophony's and Snow's test vectors

use std::{fmt, marker::PhantomData, ops::Deref};

use hex::FromHex;
use nivalis::{
    builder::NewBuilder,
    crypto::{
        cipher::{Cipher, aesgcm::AesGcm, chacha20::ChaChaPoly},
        dh::{DH, DHKeypair, x448::X448dh, x25519::X25519dh},
        hash::{Hash, blake2b::Blake2b, blake2s::Blake2s, sha256::Sha256, sha512::Sha512},
    },
    patterns::roles::{Initiator, Responder},
    patterns::*,
    state::{cipher_state::CipherState, handshake_state::{HandshakeResult, HandshakeState}},
    types::Psk
};
use serde::{
    Deserialize, Serialize,
    de::{self, Deserializer, Unexpected, Visitor},
    ser::Serializer,
};

#[derive(Clone)]
struct HexBytes<T> {
    original: String,
    payload: T,
}

impl<T: AsRef<[u8]>> From<T> for HexBytes<T> {
    fn from(payload: T) -> Self {
        Self {
            original: hex::encode(&payload),
            payload,
        }
    }
}

impl<T> Deref for HexBytes<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl<T> fmt::Debug for HexBytes<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.original)
    }
}

struct HexBytesVisitor<T: AsRef<[u8]>>(PhantomData<T>);
impl<T: AsRef<[u8]> + FromHex> Visitor<'_> for HexBytesVisitor<T> {
    type Value = HexBytes<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a hex string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes =
            T::from_hex(s).map_err(|_| de::Error::invalid_value(Unexpected::Str(s), &self))?;
        Ok(HexBytes {
            original: s.to_owned(),
            payload: bytes,
        })
    }
}

impl<'de, T: AsRef<[u8]> + FromHex> Deserialize<'de> for HexBytes<T> {
    fn deserialize<D>(deserializer: D) -> Result<HexBytes<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(HexBytesVisitor(PhantomData))
    }
}

impl<T: AsRef<[u8]>> Serialize for HexBytes<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.payload))
    }
}

#[derive(Serialize, Deserialize)]
struct TestMessage {
    payload: HexBytes<Vec<u8>>,
    ciphertext: HexBytes<Vec<u8>>,
}

impl fmt::Debug for TestMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Message")
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TestVector {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    protocol_name: String,

    init_prologue: HexBytes<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    init_psks: Option<Vec<HexBytes<[u8; 32]>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    init_static: Option<HexBytes<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    init_ephemeral: Option<HexBytes<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    init_remote_static: Option<HexBytes<Vec<u8>>>,

    resp_prologue: HexBytes<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_psks: Option<Vec<HexBytes<[u8; 32]>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_static: Option<HexBytes<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_ephemeral: Option<HexBytes<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_remote_static: Option<HexBytes<Vec<u8>>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    handshake_hash: Option<HexBytes<Vec<u8>>>,

    messages: Vec<TestMessage>,
}

#[derive(Serialize, Deserialize)]
struct TestVectors {
    vectors: Vec<TestVector>,
}

fn parse_protocol_name(name: &str) -> Option<(&str, &str, &str, &str)> {
    let mut parts = name.split('_');
    let _noise = parts.next()?;
    let pattern = parts.next()?;
    let dh = parts.next()?;
    let cipher = parts.next()?;
    let hash = parts.next()?;
    Some((pattern, dh, cipher, hash))
}

macro_rules! with_ciphersuite {
    ($p:ty, $dh:expr, $cipher:expr, $hash:expr, $vector:expr) => {
        match ($dh, $cipher, $hash) {
            ("25519", "AESGCM", "BLAKE2b") => run_vector::<$p, X25519dh, AesGcm, Blake2b>($vector),
            ("25519", "AESGCM", "BLAKE2s") => run_vector::<$p, X25519dh, AesGcm, Blake2s>($vector),
            ("25519", "AESGCM", "SHA256") => run_vector::<$p, X25519dh, AesGcm, Sha256>($vector),
            ("25519", "AESGCM", "SHA512") => run_vector::<$p, X25519dh, AesGcm, Sha512>($vector),
            ("25519", "ChaChaPoly", "BLAKE2b") => {
                run_vector::<$p, X25519dh, ChaChaPoly, Blake2b>($vector)
            }
            ("25519", "ChaChaPoly", "BLAKE2s") => {
                run_vector::<$p, X25519dh, ChaChaPoly, Blake2s>($vector)
            }
            ("25519", "ChaChaPoly", "SHA256") => {
                run_vector::<$p, X25519dh, ChaChaPoly, Sha256>($vector)
            }
            ("25519", "ChaChaPoly", "SHA512") => {
                run_vector::<$p, X25519dh, ChaChaPoly, Sha512>($vector)
            }
            ("448", "AESGCM", "BLAKE2b") => run_vector::<$p, X448dh, AesGcm, Blake2b>($vector),
            ("448", "AESGCM", "BLAKE2s") => run_vector::<$p, X448dh, AesGcm, Blake2s>($vector),
            ("448", "AESGCM", "SHA256") => run_vector::<$p, X448dh, AesGcm, Sha256>($vector),
            ("448", "AESGCM", "SHA512") => run_vector::<$p, X448dh, AesGcm, Sha512>($vector),
            ("448", "ChaChaPoly", "BLAKE2b") => {
                run_vector::<$p, X448dh, ChaChaPoly, Blake2b>($vector)
            }
            ("448", "ChaChaPoly", "BLAKE2s") => {
                run_vector::<$p, X448dh, ChaChaPoly, Blake2s>($vector)
            }
            ("448", "ChaChaPoly", "SHA256") => {
                run_vector::<$p, X448dh, ChaChaPoly, Sha256>($vector)
            }
            ("448", "ChaChaPoly", "SHA512") => {
                run_vector::<$p, X448dh, ChaChaPoly, Sha512>($vector)
            }
            (dh, cipher, hash) => Err(format!("unsupported combo: {dh}_{cipher}_{hash}")),
        }
    };
}

fn run_vector_dispatch(vector: &TestVector) -> Result<(), String> {
    let (pattern, dh, cipher, hash) = parse_protocol_name(&vector.protocol_name)
        .ok_or_else(|| format!("unparseable protocol name: {}", vector.protocol_name))?;

    match pattern {
        "N" => with_ciphersuite!(N, dh, cipher, hash, vector),
        "X" => with_ciphersuite!(X, dh, cipher, hash, vector),
        "K" => with_ciphersuite!(K, dh, cipher, hash, vector),
        "NN" => with_ciphersuite!(NN, dh, cipher, hash, vector),
        "NK" => with_ciphersuite!(NK, dh, cipher, hash, vector),
        "NX" => with_ciphersuite!(NX, dh, cipher, hash, vector),
        "XN" => with_ciphersuite!(XN, dh, cipher, hash, vector),
        "XK" => with_ciphersuite!(XK, dh, cipher, hash, vector),
        "XX" => with_ciphersuite!(XX, dh, cipher, hash, vector),
        "KN" => with_ciphersuite!(KN, dh, cipher, hash, vector),
        "KK" => with_ciphersuite!(KK, dh, cipher, hash, vector),
        "KX" => with_ciphersuite!(KX, dh, cipher, hash, vector),
        "IN" => with_ciphersuite!(IN, dh, cipher, hash, vector),
        "IK" => with_ciphersuite!(IK, dh, cipher, hash, vector),
        "IX" => with_ciphersuite!(IX, dh, cipher, hash, vector),
        "Npsk0" => with_ciphersuite!(Npsk0, dh, cipher, hash, vector),
        "Kpsk0" => with_ciphersuite!(Kpsk0, dh, cipher, hash, vector),
        "Xpsk1" => with_ciphersuite!(Xpsk1, dh, cipher, hash, vector),
        "NNpsk0" => with_ciphersuite!(NNpsk0, dh, cipher, hash, vector),
        "NNpsk2" => with_ciphersuite!(NNpsk2, dh, cipher, hash, vector),
        "NKpsk0" => with_ciphersuite!(NKpsk0, dh, cipher, hash, vector),
        "NKpsk2" => with_ciphersuite!(NKpsk2, dh, cipher, hash, vector),
        "NXpsk2" => with_ciphersuite!(NXpsk2, dh, cipher, hash, vector),
        "XNpsk3" => with_ciphersuite!(XNpsk3, dh, cipher, hash, vector),
        "XKpsk3" => with_ciphersuite!(XKpsk3, dh, cipher, hash, vector),
        "XXpsk3" => with_ciphersuite!(XXpsk3, dh, cipher, hash, vector),
        "KNpsk0" => with_ciphersuite!(KNpsk0, dh, cipher, hash, vector),
        "KNpsk2" => with_ciphersuite!(KNpsk2, dh, cipher, hash, vector),
        "KKpsk0" => with_ciphersuite!(KKpsk0, dh, cipher, hash, vector),
        "KKpsk2" => with_ciphersuite!(KKpsk2, dh, cipher, hash, vector),
        "KXpsk2" => with_ciphersuite!(KXpsk2, dh, cipher, hash, vector),
        "INpsk1" => with_ciphersuite!(INpsk1, dh, cipher, hash, vector),
        "INpsk2" => with_ciphersuite!(INpsk2, dh, cipher, hash, vector),
        "IKpsk1" => with_ciphersuite!(IKpsk1, dh, cipher, hash, vector),
        "IKpsk2" => with_ciphersuite!(IKpsk2, dh, cipher, hash, vector),
        "IXpsk2" => with_ciphersuite!(IXpsk2, dh, cipher, hash, vector),
        other => Err(format!("unsupported pattern: {other}")),
    }
}

fn run_vector<P: Pattern, D: DH, C: Cipher, H: Hash>(vector: &TestVector) -> Result<(), String> {
    let mut init_local_static = None;
    let mut init_remote_static = None;
    let mut init_local_ephemeral = None;
    let init_remote_ephemeral = None;
    let mut init_psks: Option<Psk> = None;

    let mut resp_local_static = None;
    let mut resp_remote_static = None;
    let mut resp_local_ephemeral = None;
    let resp_remote_ephemeral = None;
    let mut resp_psks: Option<Psk> = None;

    if let Some(psk) = &vector.init_psks && !psk.is_empty(){
        init_psks = Some(psk[0].payload);
    }
    if let Some(psk) = &vector.resp_psks && !psk.is_empty() {
        resp_psks = Some(psk[0].payload);
    }

    if let Some(s) = &vector.init_static {
        init_local_static =
            Some(D::privkey_from_bytes(s).map_err(|e| format!("bad init_static: {e}"))?);
    }
    if let Some(s) = &vector.resp_static {
        resp_local_static =
            Some(D::privkey_from_bytes(s).map_err(|e| format!("bad resp_static: {e}"))?);
    }
    if let Some(e) = &vector.init_ephemeral {
        init_local_ephemeral =
            Some(D::privkey_from_bytes(e).map_err(|e| format!("bad init_ephemeral: {e}"))?);
    }
    if let Some(e) = &vector.resp_ephemeral {
        resp_local_ephemeral =
            Some(D::privkey_from_bytes(e).map_err(|e| format!("bad resp_ephemeral: {e}"))?);
    }

    if vector.init_remote_static.is_some() {
        let resp_static = vector
            .resp_static
            .as_ref()
            .ok_or_else(|| "init_remote_static set but resp_static missing".to_string())?;
        let resp_sk = D::privkey_from_bytes(resp_static)
            .map_err(|e| format!("bad resp_static (for remote derivation): {e}"))?;
        let pk = D::Keypair::derive_keypair(&resp_sk);
        init_remote_static = Some(pk.public());
    }
    if vector.resp_remote_static.is_some() {
        let init_static = vector
            .init_static
            .as_ref()
            .ok_or_else(|| "resp_remote_static set but init_static missing".to_string())?;
        let init_sk = D::privkey_from_bytes(init_static)
            .map_err(|e| format!("bad init_static (for remote derivation): {e}"))?;
        let pk = D::Keypair::derive_keypair(&init_sk).public();
        resp_remote_static = Some(pk);
    }

    let mut init_hs = NewBuilder::<P, Initiator, D, C, H>::from_parts(
        init_local_static,
        init_remote_static,
        init_local_ephemeral,
        init_remote_ephemeral,
        init_psks,
        vector.init_prologue.deref().clone(),
    )
    .map_err(|e| format!("init build: {e}"))?;

    let mut resp_hs = NewBuilder::<P, Responder, D, C, H>::from_parts(
        resp_local_static,
        resp_remote_static,
        resp_local_ephemeral,
        resp_remote_ephemeral,
        resp_psks,
        vector.resp_prologue.deref().clone(),
    )
    .map_err(|e| format!("resp build: {e}"))?;

    confirm_message_vectors::<P, D, C, H>(&mut init_hs, &mut resp_hs, vector)
}

fn confirm_message_vectors<P: Pattern, D: DH, C: Cipher, H: Hash>(
    init_hs: &mut HandshakeState<P, Initiator, D, C, H>,
    resp_hs: &mut HandshakeState<P, Responder, D, C, H>,
    vector: &TestVector,
) -> Result<(), String> {
    let messages = &vector.messages;
    let handshake_msg_count = P::HANDSHAKE.messages().len();

    let mut wire = vec![0u8; 65535];
    let mut recv = vec![0u8; 65535];

    let mut init_send: Option<CipherState<C>> = None;
    let mut init_recv: Option<CipherState<C>> = None;
    let mut resp_send: Option<CipherState<C>> = None;
    let mut resp_recv: Option<CipherState<C>> = None;

    // Handshake phase
    for i in 0..handshake_msg_count {
        let message = &messages[i];
        let sender_is_init = i % 2 == 0;

        macro_rules! exchange {
            ($send:expr, $recv:expr) => {{
                let send_res = $send
                    .write_message(&message.payload, &mut wire)
                    .map_err(|e| format!("write_message failed on message {i}: {e:?}"))?;

                let (len, send_ciphers) = match send_res {
                    HandshakeResult::Continue { bytes } => (bytes, None),
                    HandshakeResult::Complete {
                        bytes_written,
                        initiator,
                        responder,
                        handshake_hash,
                    } => (bytes_written, Some((initiator, responder, handshake_hash))),
                };

                if wire[..len] != (*message.ciphertext)[..] {
                    return Err(format!(
                        "message {i} ciphertext mismatch\n  expected: {}\n  actual:   {}",
                        hex::encode(&*message.ciphertext),
                        hex::encode(&wire[..len])
                    ));
                }

                let recv_res = $recv
                    .read_message(&wire[..len], &mut recv[..message.payload.len()])
                    .map_err(|e| format!("read_message failed on message {i}: {e:?}"))?;

                if *message.payload != recv[..message.payload.len()] {
                    return Err(format!("message {i} payload mismatch on receive"));
                }

                let recv_ciphers = match recv_res {
                    HandshakeResult::Continue { .. } => None,
                    HandshakeResult::Complete {
                        initiator,
                        responder,
                        handshake_hash,
                        ..
                    } => Some((initiator, responder, handshake_hash)),
                };

                (send_ciphers, recv_ciphers)
            }};
        }

        let (send_ciphers, recv_ciphers) = if sender_is_init {
            exchange!(init_hs, resp_hs)
        } else {
            exchange!(resp_hs, init_hs)
        };

        // Whichever side reports Complete, assign ciphers to the right owner.
        if let Some((init_dir, resp_dir, hh)) = send_ciphers {
            let (init_k, init_n) = init_dir.into_parts();
            let (resp_k, resp_n) = resp_dir.into_parts();

            init_send = Some(CipherState::from_parts(init_k.clone(), init_n));
            resp_recv = Some(CipherState::from_parts(init_k, init_n));
            resp_send = Some(CipherState::from_parts(resp_k.clone(), resp_n));
            init_recv = Some(CipherState::from_parts(resp_k, resp_n));

            if let Some(expected_hh) = &vector.handshake_hash {
                if hh != **expected_hh {
                    return Err(format!(
                        "handshake_hash mismatch (sender)\n  expected: {}\n  actual:   {}",
                        hex::encode(&**expected_hh),
                        hex::encode(&hh)
                    ));
                }
            }
        }
        if let Some((_, _, hh)) = recv_ciphers {
            if let Some(expected_hh) = &vector.handshake_hash {
                if hh != **expected_hh {
                    return Err(format!(
                        "handshake_hash mismatch (receiver)\n  expected: {}\n  actual:   {}",
                        hex::encode(&**expected_hh),
                        hex::encode(&hh)
                    ));
                }
            }
        }
    }

    // Transport phase
    let is_oneway = P::HANDSHAKE.is_oneway();
    let (mut init_send, mut init_recv, mut resp_send, mut resp_recv) = (
        init_send.ok_or_else(|| "handshake never completed (init_send missing)".to_string())?,
        init_recv.ok_or_else(|| "handshake never completed (init_recv missing)".to_string())?,
        resp_send.ok_or_else(|| "handshake never completed (resp_send missing)".to_string())?,
        resp_recv.ok_or_else(|| "handshake never completed (resp_recv missing)".to_string())?,
    );

    for (i, message) in messages.iter().enumerate().skip(handshake_msg_count) {
        let (send, recv_cs) = if is_oneway || i % 2 == 0 {
            (&mut init_send, &mut resp_recv)
        } else {
            (&mut resp_send, &mut init_recv)
        };

        let mut ct = vec![0u8; message.payload.len() + 32]; // headroom for auth tag
        let ct_len = send
            .encrypt_with_ad(b"", &message.payload, &mut ct)
            .map_err(|e| format!("encrypt failed on message {i}: {e}"))?;

        if ct[..ct_len] != (*message.ciphertext)[..] {
            return Err(format!(
                "message {i} ciphertext mismatch\n  expected: {}\n  actual:   {}",
                hex::encode(&*message.ciphertext),
                hex::encode(&ct[..ct_len])
            ));
        }

        let mut recovered = vec![0u8; message.payload.len()];
        recv_cs
            .decrypt_with_ad(b"", &ct[..ct_len], &mut recovered)
            .map_err(|e| format!("decrypt failed on message {i}: {e}"))?;

        if recovered != *message.payload {
            return Err(format!("message {i} payload mismatch on transport decrypt"));
        }
    }

    Ok(())
}

fn test_vectors_from_json(json: &str) {
    let test_vectors: TestVectors = serde_json::from_str(json).unwrap();

    let mut passes = 0;
    let mut fails = 0;
    let mut ignored = 0;

    for vector in &test_vectors.vectors {
        match run_vector_dispatch(vector) {
            Ok(()) => passes += 1,
            Err(s) if s.starts_with("unsupported") || s.starts_with("unparseable") => {
                ignored += 1;
            }
            Err(s) => {
                fails += 1;
                println!("FAIL: {}", vector.protocol_name);
                println!("{s}");
            }
        }
    }

    println!("\n{}/{} passed", passes, passes + fails);
    println!("* ignored {ignored} unsupported variants");
    assert!(fails == 0, "at least one vector failed.");

    println!("All {} tests passed !", passes);
}

#[test]
fn test_vectors_cacophony() {
    test_vectors_from_json(include_str!("vectors/cacophony.txt"));
}

#[test]
fn test_vectors_snow() {
    test_vectors_from_json(include_str!("vectors/snow.txt"));
}
