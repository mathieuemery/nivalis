/-
A Lean port of the parts of nivalis that decide whether a handshake has the keys
it needs:

* `src/patterns/mod.rs`   — `HandshakePattern::{has_psk, local_static_required, …}`
* `src/patterns/roles.rs` — `PatternRequirements` (the five `*_REQUIRED` flags)
* `src/builder.rs`        — the `const { assert!(…) }` block of `build()`
* `src/state/handshake_state.rs` — `initialize`, `write_message`, `read_message`,
  `mix_ee/es/se/ss/psk`, restricted to *key presence*.

Patterns are ScalingTrust's `Noise.HandshakePattern`.

What the handshake model keeps: which of the `Option` fields of `HandshakeKeys`
(`s`, `e`, `rs`, `re`, `psk`) are `Some`, the `e_set` flag, and every error that
is raised because one of those is in the wrong state (`MissingRequirements(_)`,
`InvalidState("e must be empty")`, `InvalidState("re must be empty")`,
`InvalidState("rs must be empty")`).

What it drops: key and message *contents*.  Buffer-size and length errors,
`pubkey_from_bytes` failures, AEAD failures and nonce exhaustion are all about
bytes, not about which keys were supplied, and are out of scope.  A run is an
honest one: each party calls `write_message` on its own turns and
`read_message` on the peer's, in order, and the peer's messages decrypt.
-/
import ScalingTrust.Noise.Pattern

namespace NivalisProof
open Noise

/-! ## `src/patterns/mod.rs` -/

/-- `has_psk`: does any message contain `Token::PSK`? -/
def hasPsk (p : HandshakePattern) : Bool :=
  p.messages.any (fun m => m.contains .psk)

/-- `own_pre` in `local_static_required` / `local_ephemeral_required`. -/
def ownPre (p : HandshakePattern) (isInit : Bool) : PreMessagePattern :=
  if isInit then p.initiatorPre else p.responderPre

/-- `peer_pre` in `peer_static_is_premessage` / `peer_ephemeral_is_premessage`. -/
def peerPre (p : HandshakePattern) (isInit : Bool) : PreMessagePattern :=
  if isInit then p.responderPre else p.initiatorPre

/-- The `while i < self.messages.len()` loop of `local_static_required`, from
index `i`: some message sent by this role (`i % 2 == 0` is the initiator)
contains `Token::S`. -/
def ownSendsS (isInit : Bool) : Nat → List MessagePattern → Bool
  | _, [] => false
  | i, m :: ms => ((i % 2 == 0) == isInit && m.contains .s) || ownSendsS isInit (i + 1) ms

/-- `local_static_required`. -/
def localStaticRequired (p : HandshakePattern) (isInit : Bool) : Bool :=
  (ownPre p isInit).contains .s || ownSendsS isInit 0 p.messages

/-- `peer_static_is_premessage`. -/
def peerStaticIsPremessage (p : HandshakePattern) (isInit : Bool) : Bool :=
  (peerPre p isInit).contains .s

/-- `local_ephemeral_required` (only looks at the pre-message, as documented). -/
def localEphemeralRequired (p : HandshakePattern) (isInit : Bool) : Bool :=
  (ownPre p isInit).contains .e

/-- `peer_ephemeral_is_premessage`. -/
def peerEphemeralIsPremessage (p : HandshakePattern) (isInit : Bool) : Bool :=
  (peerPre p isInit).contains .e

/-! ## `src/patterns/roles.rs` and `src/builder.rs` -/

/-- Five booleans in the order `LS, RS, LE, RE, PSK`.  Used both for the
`PatternRequirements` constants and for the builder's typestate parameters
(which keys the user supplied). -/
structure Flags where
  ls : Bool
  rs : Bool
  le : Bool
  re : Bool
  psk : Bool
  deriving DecidableEq, Repr

/-- `impl<P: Pattern, R: RoleMarker> PatternRequirements<R> for P`. -/
def requirements (p : HandshakePattern) (isInit : Bool) : Flags where
  ls := localStaticRequired p isInit
  rs := peerStaticIsPremessage p isInit
  le := localEphemeralRequired p isInit
  re := peerEphemeralIsPremessage p isInit
  psk := hasPsk p

/-- The first five asserts of `build()` (`LS || !P::LOCAL_STATIC_REQUIRED`, …):
every required key was supplied.  These were the only checks up to v0.3.2. -/
def hasRequired (req sup : Flags) : Bool :=
  (sup.ls || !req.ls) && (sup.rs || !req.rs) && (sup.le || !req.le) &&
  (sup.re || !req.re) && (sup.psk || !req.psk)

/-- The last two asserts of `build()` (`!RS || P::REMOTE_STATIC_REQUIRED`,
`!RE || P::REMOTE_EPHEMERAL_REQUIRED`): no remote key was supplied that is not
a pre-message. -/
def noUnexpected (req sup : Flags) : Bool :=
  (!sup.rs || req.rs) && (!sup.re || req.re)

/-- The whole `const { … }` block of `build()`: `true` iff `build()` compiles
for a builder whose typestate flags are `sup`.  `from_parts` performs the same
checks at run time. -/
def buildAccepts (req sup : Flags) : Bool :=
  hasRequired req sup && noUnexpected req sup

/-! ## `src/state/handshake_state.rs`, key presence only -/

/-- `MissingKey`. -/
inductive MissingKey
  | localStatic | remoteStatic | localEphemeral | remoteEphemeral | psk
  deriving DecidableEq, Repr

/-- The key-related subset of `NoiseError`. -/
inductive Err
  | missing (k : MissingKey)
  | invalidState (msg : String)
  deriving DecidableEq, Repr

/-- Which `Option`s of `HandshakeKeys` are `Some`, plus `HandshakeState::e_set`. -/
structure Keys where
  s : Bool
  e : Bool
  rs : Bool
  re : Bool
  psk : Bool
  eSet : Bool
  deriving DecidableEq, Repr

/-- `x.as_ref().ok_or(MissingRequirements(k))?` -/
def require (b : Bool) (k : MissingKey) : Except Err Unit :=
  if b then .ok () else .error (.missing k)

/-- Two `ok_or(…)?` in a row. -/
def require2 (b₁ : Bool) (k₁ : MissingKey) (b₂ : Bool) (k₂ : MissingKey) : Except Err Unit :=
  if b₁ then require b₂ k₂ else .error (.missing k₁)

/-- `mix_ee`: `e`, then `re`. -/
def mixEE (k : Keys) : Except Err Unit := require2 k.e .localEphemeral k.re .remoteEphemeral

/-- `mix_es`: initiator `DH(e, rs)`, responder `DH(s, re)`. -/
def mixES (isInit : Bool) (k : Keys) : Except Err Unit :=
  if isInit then require2 k.e .localEphemeral k.rs .remoteStatic
  else require2 k.s .localStatic k.re .remoteEphemeral

/-- `mix_se`: initiator `DH(s, re)`, responder `DH(e, rs)`. -/
def mixSE (isInit : Bool) (k : Keys) : Except Err Unit :=
  if isInit then require2 k.s .localStatic k.re .remoteEphemeral
  else require2 k.e .localEphemeral k.rs .remoteStatic

/-- `mix_ss`: `s`, then `rs`. -/
def mixSS (k : Keys) : Except Err Unit := require2 k.s .localStatic k.rs .remoteStatic

/-- `mix_psk`. -/
def mixPsk (k : Keys) : Except Err Unit := require k.psk .psk

/-- Run a check, keeping the keys unchanged on success. -/
def andThen (r : Except Err Unit) (k : Keys) : Except Err Keys :=
  match r with
  | .ok () => .ok k
  | .error e => .error e

/-- The token loop of `write_message`. -/
def writeToken (isInit : Bool) (k : Keys) : Token → Except Err Keys
  -- `if self.e_set { Err(InvalidState("e must be empty")) }`; otherwise take the
  -- supplied `e` or `D::generate_keypair`, then `self.keys.e = Some(e); self.e_set = true`.
  | .key .e => if k.eSet then .error (.invalidState "e must be empty")
               else .ok { k with e := true, eSet := true }
  -- `self.keys.s.as_ref().ok_or(MissingRequirements(LocalStatic))?`
  | .key .s => andThen (require k.s .localStatic) k
  | .dh .e .e => andThen (mixEE k) k
  | .dh .e .s => andThen (mixES isInit k) k
  | .dh .s .e => andThen (mixSE isInit k) k
  | .dh .s .s => andThen (mixSS k) k
  | .psk => andThen (mixPsk k) k

/-- The token loop of `read_message`. -/
def readToken (isInit : Bool) (k : Keys) : Token → Except Err Keys
  -- `if self.keys.re.is_some() { Err(InvalidState("re must be empty")) }`; then
  -- `self.keys.re = Some(re)`.
  | .key .e => if k.re then .error (.invalidState "re must be empty")
               else .ok { k with re := true }
  -- `if self.keys.rs.is_some() { Err(InvalidState("rs must be empty")) }`; then
  -- `self.keys.rs = Some(D::pubkey_from_bytes(…)?)`.
  | .key .s => if k.rs then .error (.invalidState "rs must be empty")
               else .ok { k with rs := true }
  | .dh .e .e => andThen (mixEE k) k
  | .dh .e .s => andThen (mixES isInit k) k
  | .dh .s .e => andThen (mixSE isInit k) k
  | .dh .s .s => andThen (mixSS k) k
  | .psk => andThen (mixPsk k) k

/-- All tokens of one message, written (`mine`) or read. -/
def runTokens (isInit mine : Bool) : Keys → List Token → Except Err Keys
  | k, [] => .ok k
  | k, t :: ts =>
      match (if mine then writeToken isInit k t else readToken isInit k t) with
      | .ok k' => runTokens isInit mine k' ts
      | .error e => .error e

/-- The handshake messages from index `i`.  Message `i` is written by this
party when `(i % 2 == 0) == R::IS_INITIATOR` and read otherwise. -/
def runMessages (isInit : Bool) : Nat → Keys → List MessagePattern → Except Err Keys
  | _, k, [] => .ok k
  | i, k, m :: ms =>
      match runTokens isInit ((i % 2 == 0) == isInit) k m with
      | .ok k' => runMessages isInit (i + 1) k' ms
      | .error e => .error e

/-- `mix_pre_messages_init`, one pre-message key. -/
def preLocal (k : Keys) : KeyKind → Except Err Unit
  | .s => require k.s .localStatic
  | .e => require k.e .localEphemeral

/-- `mix_pre_messages_remote`, one pre-message key. -/
def preRemote (k : Keys) : KeyKind → Except Err Unit
  | .s => require k.rs .remoteStatic
  | .e => require k.re .remoteEphemeral

/-- `for token in tokens { … }` over a pre-message. -/
def preAll (f : KeyKind → Except Err Unit) : List KeyKind → Except Err Unit
  | [] => .ok ()
  | x :: xs =>
      match f x with
      | .ok () => preAll f xs
      | .error e => .error e

/-- `HandshakeState::initialize`: the initiator mixes its own pre-message and
then the responder's; the responder mixes the initiator's (as remote) and then
its own. -/
def initializeHS (p : HandshakePattern) (isInit : Bool) (k : Keys) : Except Err Unit :=
  if isInit then
    match preAll (preLocal k) p.initiatorPre with
    | .ok () => preAll (preRemote k) p.responderPre
    | .error e => .error e
  else
    match preAll (preRemote k) p.initiatorPre with
    | .ok () => preAll (preLocal k) p.responderPre
    | .error e => .error e

/-- The `HandshakeKeys` that `build()` passes to `initialize`: exactly the keys
the user supplied (`local_static_key`, `local_ephemeral_key`, …). -/
def Keys.ofSupplied (sup : Flags) : Keys where
  s := sup.ls
  e := sup.le
  rs := sup.rs
  re := sup.re
  psk := sup.psk
  eSet := false

/-- `build()` followed by an honest run of the whole handshake.  On success the
returned `Keys.rs` says whether `TransportState::remote_static_pk()` is `Some`
(`let remote_pk = self.keys.rs.take();` at the end of the last message). -/
def handshake (p : HandshakePattern) (isInit : Bool) (sup : Flags) : Except Err Keys :=
  match initializeHS p isInit (Keys.ofSupplied sup) with
  | .ok () => runMessages isInit 0 (Keys.ofSupplied sup) p.messages
  | .error e => .error e

/-- Did the run succeed? -/
def isOk : Except Err Keys → Bool
  | .ok _ => true
  | .error _ => false

end NivalisProof
