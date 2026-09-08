//! # nivalis
//!
//! A typestate-driven, pure-Rust implementation of the [Noise Protocol
//! Framework](https://noiseprotocol.org/noise.html) (revision 34).
//!
//! ## Overview
//!
//! Nivalis uses Rust's type system to enforce the Noise handshake state
//! machine at compile time, making it impossible to call handshake
//! methods out of order or reuse a completed session.
//!
//! ## Quick start
//!
//! The following example shows you how to create the builders for
//! the IK pattern:
//! ```rust
//! use nivalis::{
//!    builder::NewBuilder,
//!    crypto::{cipher::chacha20::ChaChaPoly, dh::{DH, DHKeypair, x25519::X25519dh}, hash::blake2s::Blake2s},
//!    patterns::{IK, roles::{Initiator, Responder}},
//!};
//!
//!let init_static = X25519dh::generate_keypair();
//!let resp_static = X25519dh::generate_keypair();
//!
//!let initiator = NewBuilder::<IK, Initiator, X25519dh, ChaChaPoly, Blake2s>::new()
//!        .local_static_key(init_static.private().clone())
//!        .remote_static_key(resp_static.public())
//!        .build()
//!        .expect("failed to build initiator handshake state");
//!
//!let responder = NewBuilder::<IK, Responder, X25519dh, ChaChaPoly, Blake2s>::new()
//!        .local_static_key(resp_static.private().clone())
//!        .build()
//!        .expect("failed to build responder handshake state");
//! // ...
//! ```
//!
//! ## Modules
//!
//! - [`builder`] — typestate builder for the Noise handshake
//! - [`crypto`] — cryptographic primitives (AEAD, hashing, DH)
//! - [`patterns`] — the standard Noise patterns (NN, XX, IK, etc.)
//! - [`state`] — handshake/session state types
//! - [`error`] / [`types`] — shared error and data types

#![no_std]

pub mod builder;
mod constants;
pub mod crypto;
pub mod error;
pub mod patterns;
pub mod state;
pub mod types;
