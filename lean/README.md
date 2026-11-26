# Lean proof of the builder checks

This directory has a Lean 4 proof about the `const` asserts in
`HandshakeParamsBuilder::build()`. If `build()` compiles, the handshake doesn't
fail because a key is missing or was supplied when it shouldn't have been. When
the handshake finishes, `TransportState::remote_static_pk()` returns a key
only if the peer's static key was part of the handshake.

The Noise side (handshake patterns and the validity rules from spec §7.3 and
§9.3) comes from the Noise library in
[ScalingTrust](https://github.com/artie2000/ScalingTrust), which is declared as a
Lake dependency. The files here only model nivalis.

## Building

```sh
cd lean
lake build
```

This needs elan (it picks Lean 4.33.0 from `lean-toolchain`). The first build
clones ScalingTrust and its dependencies, about 730 MB, most of it Mathlib's git
history, and takes a minute or so. Nothing from Mathlib gets compiled. If you run
`lake update`, set `MATHLIB_NO_CACHE_ON_UPDATE=1`, or Mathlib downloads its
build cache (about 6 GB), which this project doesn't need.

CI (`.github/workflows/lean.yml`) builds the proof. It also checks that
`NivalisProof/Patterns.lean` matches `src/patterns/mod.rs`.

## Files

- `gen_patterns.py` generates `NivalisProof/Patterns.lean` from
  `src/patterns/mod.rs`.
- `NivalisProof/Model.lean` ports the parts of `patterns/mod.rs`,
  `patterns/roles.rs`, `builder.rs` and `state/handshake_state.rs` that decide
  which keys are required and when a missing or already-set key causes an error.
- `NivalisProof/Soundness.lean` holds the general theorem.
- `NivalisProof/Shipped.lean` holds results about the 36 patterns in the crate.

## What is proved

- `builder_sound`: for any pattern that is valid according to ScalingTrust's
  `PatternValid`, for both roles, and for every set of keys that `build()`
  accepts, the handshake completes without a key error. At the end, the
  remote static key is set iff the peer's static key was sent or was a
  pre-message.
- `nivalis_patterns_eq`: the patterns in `src/patterns/mod.rs` are the same as
  the one-way, fundamental and PSK patterns in ScalingTrust, which are taken
  from the Noise spec.
- `nivalis_exact`: for the 36 patterns, both roles and all 32 combinations of
  supplied keys, when no unexpected remote key is supplied, the handshake
  succeeds iff all required keys were supplied. So the "missing key" asserts
  never reject a setup that would have worked.
- `unexpected_re_NN`, `unexpected_rs_NN`: the two setups that compiled before
  this change and now don't:
  - an `NN` initiator given a remote ephemeral key, whose handshake then
    failed with `InvalidState("re must be empty")`;
  - an `NN` responder given a remote static key, which ended up in
    `remote_static_pk()` without being authenticated.

There is no `sorry`, `admit` or `native_decide`. The only axioms used are
Lean's standard `propext`, `Classical.choice` and `Quot.sound`.

## Limits

- The model only tracks which keys are present (the `Option`s in
  `HandshakeKeys` and the `e_set` flag). It does not model message bytes,
  buffer sizes, DH or AEAD failures, or nonce limits.
- It assumes both sides follow the protocol: each writes its own messages in
  order and successfully reads the other's.
- `Model.lean` was written by hand to follow the Rust closely, but nothing
  checks it against the Rust automatically. If `builder.rs` or
  `handshake_state.rs` changes in a way that affects keys, `Model.lean` has to
  be updated too.
- The pattern table is generated, and CI checks that it is up to date.
