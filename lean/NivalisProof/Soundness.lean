/-
**The builder is sound for every valid Noise pattern.**

If a pattern is valid in ScalingTrust's sense (`Noise.PatternValid`: spec §7.3
rules 1–4 and §9.3) and `build()` compiles (`buildAccepts`), then the honest
handshake never fails because of a missing or unexpected key, and at the end
the party holds a remote static key (`remote_static_pk()` is `Some`) exactly
when the peer's static key took part in the handshake.

The proof is a simulation: ScalingTrust's validity context `Ctx` records which
public keys have been communicated so far, and the invariant `Inv` relates it to
the `Keys` a nivalis party holds.
-/
import NivalisProof.Model
import ScalingTrust.Noise.Validity

namespace NivalisProof
open Noise

/-- nivalis' `R::IS_INITIATOR` as a ScalingTrust role. -/
def roleOf (isInit : Bool) : Role := if isInit then .initiator else .responder

/-- The simulation invariant between the validity context `c` and the keys `k`
held by the party `roleOf isInit`: it has every own key that has been
communicated, and it holds exactly the peer keys that have been communicated. -/
def Inv (isInit : Bool) (c : Ctx) (k : Keys) : Prop :=
  (c.hasKey (roleOf isInit) .s = true → k.s = true) ∧
  (c.hasKey (roleOf isInit) .e = true → k.e = true) ∧
  (k.eSet = true → c.hasKey (roleOf isInit) .e = true) ∧
  k.rs = c.hasKey (roleOf isInit).other .s ∧
  k.re = c.hasKey (roleOf isInit).other .e

/-- One token: a step allowed by the validity rules is also a step nivalis can
take, and it preserves the invariant. -/
theorem token_step {isInit mine : Bool} {r : Role} {c c' : Ctx} {t : Token} {k : Keys}
    (ht : TokenStep r c t c') (hm : mine = decide (r = roleOf isInit))
    (hinv : Inv isInit c k)
    (hS : mine = true → t = .s → k.s = true) (hP : t = .psk → k.psk = true) :
    ∃ k', (if mine then writeToken isInit k t else readToken isInit k t) = .ok k' ∧
      Inv isInit c' k' ∧ k'.s = k.s ∧ k'.psk = k.psk := by
  unfold Inv at hinv ⊢
  obtain ⟨ks, ke, krs, kre, kpsk, keSet⟩ := k
  obtain ⟨iE, iS, rE, rS, cee, ces, cse, css, cpsk⟩ := c
  subst hm
  cases ht with
  | ephemeral h =>
      cases isInit <;> cases r <;>
        simp_all [writeToken, readToken, roleOf, Role.other, Ctx.hasKey, Ctx.setKey]
  | static h _ =>
      cases isInit <;> cases r <;>
        simp_all [writeToken, readToken, roleOf, Role.other, Ctx.hasKey, Ctx.setKey,
          andThen, require]
  | @dh a b ha hb _ =>
      cases isInit <;> cases r <;> cases a <;> cases b <;>
        simp_all [writeToken, readToken, roleOf, Role.other, Ctx.hasKey, Ctx.setDH,
          andThen, require, require2, mixEE, mixES, mixSE, mixSS]
  | psk =>
      cases isInit <;> cases r <;>
        simp_all [writeToken, readToken, roleOf, Role.other, Ctx.hasKey, Ctx.setPsk,
          andThen, require, mixPsk]

/-- One message's tokens. -/
theorem tokens_step {isInit mine : Bool} {r : Role} {c c' : Ctx} {ts : List Token}
    (h : TokensStep r c ts c') (hm : mine = decide (r = roleOf isInit)) :
    ∀ k, Inv isInit c k → (mine = true → Token.s ∈ ts → k.s = true) →
      (Token.psk ∈ ts → k.psk = true) →
      ∃ k', runTokens isInit mine k ts = .ok k' ∧ Inv isInit c' k' ∧
        k'.s = k.s ∧ k'.psk = k.psk := by
  induction h with
  | nil => intro k hk _ _; exact ⟨k, rfl, hk, rfl, rfl⟩
  | cons ht _ ih =>
      intro k hk hS hP
      obtain ⟨k₁, h₁, hk₁, hs₁, hp₁⟩ := token_step ht hm hk
        (fun hmine ht' => hS hmine (by simp [ht'])) (fun ht' => hP (by simp [ht']))
      obtain ⟨k₂, h₂, hk₂, hs₂, hp₂⟩ := ih k₁ hk₁
        (fun hmine hmem => by rw [hs₁]; exact hS hmine (List.mem_cons_of_mem _ hmem))
        (fun hmem => by rw [hp₁]; exact hP (List.mem_cons_of_mem _ hmem))
      exact ⟨k₂, by simp [runTokens, h₁, h₂], hk₂, hs₂.trans hs₁, hp₂.trans hp₁⟩

/-- nivalis' turn test `(i % 2 == 0) == R::IS_INITIATOR` is ScalingTrust's
`senderAt i = role`. -/
theorem mine_eq (isInit : Bool) (i : Nat) :
    ((i % 2 == 0) == isInit) = decide (HandshakePattern.senderAt i = roleOf isInit) := by
  unfold HandshakePattern.senderAt roleOf
  cases isInit <;> by_cases h : i % 2 = 0 <;> simp [h]

/-- All handshake messages from index `i`. -/
theorem messages_step {isInit : Bool} :
    ∀ (ms : List MessagePattern) (i : Nat) (c cf : Ctx) (k : Keys),
      MessagesStep (HandshakePattern.senderAt i) c ms cf → Inv isInit c k →
      (ownSendsS isInit i ms = true → k.s = true) →
      (ms.any (fun m => m.contains .psk) = true → k.psk = true) →
      ∃ k', runMessages isInit i k ms = .ok k' ∧ Inv isInit cf k'
  | [], _, _, _, k, h, hk, _, _ => by cases h; exact ⟨k, rfl, hk⟩
  | m :: ms, i, c, cf, k, h, hk, hS, hP => by
      cases h with
      | cons hm hms =>
        cases hm with
        | mk hts _ =>
          obtain ⟨k₁, h₁, hk₁, hs₁, hp₁⟩ := tokens_step hts (mine_eq isInit i) k hk
            (fun hmine hmem => hS (by simp_all [ownSendsS]))
            (fun hmem => hP (by simp_all))
          rw [← HandshakePattern.senderAt_succ] at hms
          obtain ⟨k₂, h₂, hk₂⟩ := messages_step ms (i + 1) _ cf k₁ hms hk₁
            (fun h' => by rw [hs₁]; exact hS (by simp [ownSendsS, h']))
            (fun h' => by rw [hp₁]; exact hP (by simp_all))
          exact ⟨k₂, by simp [runMessages, h₁, h₂], hk₂⟩

/-! ## Pre-messages and `initialize` -/

theorem hasKey_foldl_setKey (r r' : Role) (k : KeyKind) :
    ∀ (ks : List KeyKind) (c : Ctx),
      (ks.foldl (fun c k => c.setKey r k) c).hasKey r' k =
        (c.hasKey r' k || (decide (r' = r) && ks.contains k))
  | [], c => by simp
  | k' :: ks, c => by
      rw [List.foldl_cons, hasKey_foldl_setKey r r' k ks]
      obtain ⟨iE, iS, rE, rS, cee, ces, cse, css, cpsk⟩ := c
      cases r <;> cases r' <;> cases k <;> cases k' <;> simp [Ctx.setKey, Ctx.hasKey]

/-- After the pre-messages, exactly the pre-message keys are known. -/
theorem preCtx_hasKey (p : HandshakePattern) (r : Role) (k : KeyKind) :
    (preCtx p).hasKey r k =
      (if r = .initiator then p.initiatorPre.contains k else p.responderPre.contains k) := by
  unfold preCtx
  rw [hasKey_foldl_setKey, hasKey_foldl_setKey]
  cases r <;> cases k <;> simp [Ctx.empty, Ctx.hasKey]

theorem preAll_ok (f : KeyKind → Except Err Unit) :
    ∀ (l : List KeyKind), (∀ x ∈ l, f x = .ok ()) → preAll f l = .ok ()
  | [], _ => rfl
  | x :: xs, h => by
      have hx : f x = .ok () := h x (by simp)
      simp only [preAll, hx]
      exact preAll_ok f xs (fun y hy => h y (List.mem_cons_of_mem _ hy))

/-- If `build()` compiles, `initialize` does not fail. -/
theorem initialize_ok (p : HandshakePattern) (isInit : Bool) (sup : Flags)
    (hb : buildAccepts (requirements p isInit) sup = true) :
    initializeHS p isInit (Keys.ofSupplied sup) = .ok () := by
  have hloc : ∀ x ∈ ownPre p isInit, preLocal (Keys.ofSupplied sup) x = .ok () := by
    intro x hx
    cases x <;> simp_all [preLocal, require, Keys.ofSupplied, buildAccepts, hasRequired, requirements,
      localStaticRequired, localEphemeralRequired]
  have hrem : ∀ x ∈ peerPre p isInit, preRemote (Keys.ofSupplied sup) x = .ok () := by
    intro x hx
    cases x <;> simp_all [preRemote, require, Keys.ofSupplied, buildAccepts, hasRequired, requirements,
      peerStaticIsPremessage, peerEphemeralIsPremessage]
  cases isInit <;> simp [ownPre, peerPre] at hloc hrem <;>
    simp [initializeHS, preAll_ok _ _ hrem, preAll_ok _ _ hloc]

/-- The invariant holds at the start of the first message. -/
theorem inv_init (p : HandshakePattern) (isInit : Bool) (sup : Flags)
    (hb : buildAccepts (requirements p isInit) sup = true) :
    Inv isInit (preCtx p) (Keys.ofSupplied sup) := by
  unfold Inv
  simp only [preCtx_hasKey]
  cases isInit <;>
    simp_all [roleOf, Role.other, Keys.ofSupplied, buildAccepts, hasRequired, noUnexpected,
      requirements,
      localStaticRequired, peerStaticIsPremessage, localEphemeralRequired,
      peerEphemeralIsPremessage, ownPre, peerPre] <;>
    grind

/-! ## Main theorem -/

/-- **Builder soundness.**  For every valid pattern and role: if `build()`
compiles, the honest handshake succeeds, and the party ends up holding a remote
static key exactly when the peer's static key was communicated in the handshake
(as a pre-message or by an `s` token; `finalCtx` is ScalingTrust's context at
the end of the pattern). -/
theorem builder_sound (p : HandshakePattern) (hv : PatternValid p)
    (isInit : Bool) (sup : Flags)
    (hb : buildAccepts (requirements p isInit) sup = true) :
    ∃ k, handshake p isInit sup = .ok k ∧
      k.rs = p.finalCtx.hasKey (roleOf isInit).other .s := by
  obtain ⟨hI, hR, hne, c₀, c₁, cf, h0, h1, hm, htr⟩ := hv
  have hc₁ : c₁ = preCtx p := by
    rw [preStep_eq _ _ h1, preStep_eq _ _ h0]; rfl
  have hfin : p.finalCtx = cf := by
    have e0 := (stepPre_eq_ok_iff _ _ _ _).mpr h0
    have e1 := (stepPre_eq_ok_iff _ _ _ _).mpr h1
    have em := (stepMessages_eq_ok_iff _ _ _ _).mpr hm
    have et := (checkTransport_eq_ok_iff _ _).mpr htr
    simp [HandshakePattern.finalCtx, HandshakePattern.analyse, hI, hR, hne, e0, e1, em, et]
  subst hc₁
  have hb' := hb
  simp only [buildAccepts, hasRequired, requirements, localStaticRequired, hasPsk,
    Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true'] at hb'
  obtain ⟨k, hk, hinv⟩ := messages_step p.messages 0 _ cf (Keys.ofSupplied sup)
    (by simpa using hm) (inv_init p isInit sup hb)
    (fun h => by
      simp only [Keys.ofSupplied]
      rcases hb'.1.1.1.1.1 with h' | h'
      · exact h'
      · simp_all)
    (fun h => by
      simp only [Keys.ofSupplied]
      rcases hb'.1.2 with h' | h'
      · exact h'
      · rw [h'] at h; exact absurd h (by decide))
  refine ⟨k, ?_, ?_⟩
  · simp [handshake, initialize_ok p isInit sup hb, hk]
  · rw [hfin]; exact hinv.2.2.2.1

end NivalisProof
