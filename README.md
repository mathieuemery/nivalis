# nivalis

A Rust implementation of the [Noise Protocol Framework](https://noiseprotocol.org/) revision 34.

## Why this exists

[`snow`](https://github.com/mcginty/snow) is the "official" Noise implementation in Rust that is used by most people. Although the implementation is great, the pattern/ciphersuite is passed in a string and most of the validation is done at runtime.

`nivalis` has the goal to check the validity of the pattern, role, and ciphersuite at compile time. It will also block the compilation if you didn't provided the correct keys for a given pattern using `const` assertion in the `build()` method. The goal of that is to make it almost impossible to missuse and potentially panic at runtime. It also allows you to use your IDE's auto-complete to see which patterns/ciphersuites are available.

This isn't a claim that `nivalis` is more correct than `snow` cryptographically, it is just a new API which aims to catch setup mistake earlier. The builder uses a typestate pattern where `LS`, `RS`, `LE`, `RE`, and `PSK` are `bool` const generics tracking, at compile time, which pieces have been supplied so far, and `P: PatternRequirements<R>` ties those flags to what the chosen pattern and role actually need.

Also, with `snow`, a PSK is supplied with an explicit slot index (e.g. `.psk(0, key)`), which means it's possible to build something like `IKpsk2` while actually passing the key at index `0`. `nivalis` doesn't expose an index at all, `.psk(key)` takes a single key, and the pattern itself determines where that key gets mixed into the handshake. There's exactly one PSK slot to fill, so there's no wrong slot to fill it at. The drawback of this is that it doesn't allow you to use patterns that use multiple PSKs such as `XXpsk0+psk3`.

## Available Patterns
The patterns supported by this implementation are all the one-way, interactive (fundamental), and the PSK variation presented on [Noise Explorer](https://noiseexplorer.com/patterns/).

The full list includes:
- N, K and X
- NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX
- Npsk0, Kpsk0, Xpsk1
- NNpsk0, NNpsk2, NKpsk0, NKpsk2, NXpsk2, XNpsk3, XKpsk3, XXpsk3, KNpsk0, KNpsk2, KKpsk0, KKpsk2, KXpsk2, INpsk1, INpsk2, IKpsk1, IKpsk2, IXpsk2

`Fallback` patterns are not supported yet.

## Available Ciphersuites
All cipher, dh and hash methods defined by the Noise protocol's documentation can be used.

For Cipher, it includes:
- AES-GCM
- ChaCha20-Poly1305

For DH:
- X25519
- X448

For Hash:
- Blake2b
- Blake2s
- SHA256
- SHA512

## Test vectors

`nivalis` is tested against, and passes, the full set of published test vectors from both [cacophony](https://github.com/centromere/cacophony) and [snow](https://github.com/mcginty/snow).

## Example

Building an initiator and a responder for the `IK` pattern:

```rust
use nivalis::{
    builder::NewBuilder,
    crypto::{cipher::chacha20::ChaChaPoly, dh::{DH, DHKeypair, x25519::X25519dh}, hash::blake2s::Blake2s},
    patterns::{IK, roles::{Initiator, Responder}},
};

let init_static = X25519dh::generate_keypair();
let resp_static = X25519dh::generate_keypair();

let initiator = NewBuilder::<IK, Initiator, X25519dh, ChaChaPoly, Blake2s>::new()
        .local_static_key(init_static.private().clone())
        .remote_static_key(resp_static.public())
        .build()
        .expect("failed to build initiator handshake state");

let responder = NewBuilder::<IK, Responder, X25519dh, ChaChaPoly, Blake2s>::new()
        .local_static_key(resp_static.private().clone())
        .build()
        .expect("failed to build responder handshake state");
```

If you tried to `.build()` the initiator above without calling `.remote_static_key(...)` first, the program would refuse to compile.

See `examples/` for a full handshake-to-transport walkthrough, including sending and decrypting an encrypted message once the handshake completes.

## Status

`nivalis` has **not been independently security-reviewed or audited**. It passes the standard Noise test vectors, which gives confidence in protocol-level correctness, but that is not a substitute for cryptographic review. Do not use this in a security-critical context without an audit. Use at your own risk, and please report anything that looks wrong.

## Contributing

This is very much a young project, and there's a lot of room to help: additional DH/cipher/hash backends, more handshake patterns, fuzzing, documentation, or just reading the code with a skeptical eye. Issues and PRs are welcome — if you're considering a larger change, opening an issue first to discuss the approach is appreciated.