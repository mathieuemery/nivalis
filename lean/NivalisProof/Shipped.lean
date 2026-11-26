/-
Results about the 36 patterns nivalis actually ships (`nivalisPatterns`,
generated from `src/patterns/mod.rs`).
-/
import NivalisProof.Patterns
import NivalisProof.Soundness
import ScalingTrust.Noise.PatternsValid

namespace NivalisProof
open Noise

/-! ## The pattern table -/

/-- nivalis' patterns are exactly ScalingTrust's one-way (§7.4), fundamental
(§7.5) and recommended PSK (§9.4) tables: same names, pre-messages and
messages, in the same order. -/
theorem nivalis_patterns_eq :
    nivalisPatterns = Patterns.oneWay ++ Patterns.fundamental ++ Patterns.psk := by
  decide

theorem nivalis_patterns_length : nivalisPatterns.length = 36 := by decide

/-- Every nivalis pattern is valid (spec §7.3, §9.3). -/
theorem nivalis_patterns_valid : ∀ p ∈ nivalisPatterns, PatternValid p := by
  have h : ∀ p ∈ nivalisPatterns, p.isValid = true := by decide
  exact fun p hp => (HandshakePattern.isValid_iff_patternValid p).mp (h p hp)

/-! ## Soundness, specialised -/

/-- No shipped pattern has an ephemeral pre-message, so `.local_ephemeral_key`
is never required and `.remote_ephemeral_key` is never allowed. -/
theorem nivalis_no_ephemeral_requirements :
    ∀ p ∈ nivalisPatterns, ∀ isInit : Bool,
      (requirements p isInit).le = false ∧ (requirements p isInit).re = false := by
  decide

/-- **If `build()` compiles, the handshake succeeds**, for every shipped pattern
and role, and `remote_static_pk()` is `Some` exactly when the peer's static key
took part in the handshake. -/
theorem nivalis_builder_sound (p : HandshakePattern) (hp : p ∈ nivalisPatterns)
    (isInit : Bool) (sup : Flags)
    (hb : buildAccepts (requirements p isInit) sup = true) :
    ∃ k, handshake p isInit sup = .ok k ∧
      k.rs = p.finalCtx.hasKey (roleOf isInit).other .s :=
  builder_sound p (nivalis_patterns_valid p hp) isInit sup hb

/-- **The "missing key" checks are exact**, over all 36 patterns × 2 roles ×
32 builder typestates: when no unexpected remote key is supplied, the
handshake succeeds iff every required key was supplied.  So those checks never
reject a configuration that would have worked. -/
theorem nivalis_exact :
    ∀ p ∈ nivalisPatterns, ∀ isInit ls rs le re psk : Bool,
      noUnexpected (requirements p isInit) ⟨ls, rs, le, re, psk⟩ = true →
      isOk (handshake p isInit ⟨ls, rs, le, re, psk⟩) =
        hasRequired (requirements p isInit) ⟨ls, rs, le, re, psk⟩ := by
  decide +kernel

/-! ## The two configurations that motivated `noUnexpected`

Both were accepted by v0.3.2, whose `build()` only had the `hasRequired`
asserts, and both are now compile errors. -/

/-- `NN` initiator with `.remote_ephemeral_key(pk)`: accepted by the v0.3.2
checks, then the handshake fails with `InvalidState("re must be empty")` when
the initiator reads the responder's `e`.  Now rejected by `build()`. -/
theorem unexpected_re_NN :
    hasRequired (requirements Patterns.NN true) ⟨false, false, false, true, false⟩ = true ∧
    handshake Patterns.NN true ⟨false, false, false, true, false⟩ =
      .error (.invalidState "re must be empty") ∧
    buildAccepts (requirements Patterns.NN true) ⟨false, false, false, true, false⟩ = false :=
  ⟨rfl, rfl, rfl⟩

/-- `NN` responder with `.remote_static_key(pk)`: accepted by the v0.3.2
checks, and the handshake succeeds with the responder holding a remote static
key (`remote_static_pk()` is `Some(pk)`) although the initiator's static key
never took part in the handshake.  Now rejected by `build()`. -/
theorem unexpected_rs_NN :
    hasRequired (requirements Patterns.NN false) ⟨false, true, false, false, false⟩ = true ∧
    (∃ k, handshake Patterns.NN false ⟨false, true, false, false, false⟩ = .ok k ∧
      k.rs = true) ∧
    Patterns.NN.finalCtx.hasKey .initiator .s = false ∧
    buildAccepts (requirements Patterns.NN false) ⟨false, true, false, false, false⟩ = false :=
  ⟨rfl, ⟨_, rfl, rfl⟩, by decide, rfl⟩

end NivalisProof
