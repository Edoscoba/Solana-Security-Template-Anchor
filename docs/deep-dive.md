# Deep Dive — Practical Solana Security Patterns (Anchor examples)

This document explains the security patterns demonstrated by the examples in this repository. The focus is not “bigger apps”, but small, repeatable rules that prevent common Solana exploits.

## Solana security mental model

On Solana, the caller controls:

* instruction data (arguments)
* the list of accounts passed into the instruction

Programs must treat accounts as untrusted inputs and enforce:

* **who is authorized**
* **which accounts are the intended ones**
* **which CPI targets and account sets are allowed**
* **invariants** (balances/credits/math/state transitions)

---

## 1) Authorization: pubkey equality is not enough

**Example:** `vault-missing-signer`

A check like:

* “does the provided pubkey equal the stored authority pubkey?”
  is not authorization.

Authorization requires a **signature** (or a safe PDA-signing rule), plus correct account relationships. Anchor makes this clearer with:

* `Signer<'info>`
* `has_one = authority`

**Rule of thumb:**
If an instruction changes authority or moves funds, require a signer and bind it to state.

---

## 2) Account validation: enforce PDA derivation (seeds/bump)

**Example:** `vault-pda-spoofing`

If you accept a “vault” account without proving it is the PDA derived from the expected seeds, attackers can substitute another account (including someone else’s vault).

Anchor PDA constraints:

* `seeds = [...]`
* `bump = ...`

**Rule of thumb:**
If your logic assumes “this is THE vault”, enforce the PDA address derivation, don’t assume it.

---

## 3) CPI safety: pin your CPI program id

**Example:** `vault-cpi-injection`

If the caller can choose the CPI program id, they can choose a malicious program that:

* returns success without performing side effects
* interprets accounts differently
* causes unexpected behavior

Anchor can pin CPI targets using:

* `Program<'info, ExpectedProgram>`

**Rule of thumb:**
If you CPI, treat the CPI program id as security-critical. Pin it, and validate the accounts passed into the CPI.

---

## 4) Arithmetic is security: avoid wrapping underflow/overflow

**Example:** `vault-unchecked-math`

Unsigned underflow/overflow can silently break invariants:

* credits become huge after underflow
* checks can become meaningless (“>= 0” on unsigned)

Use:

* precondition checks (`>= amount`)
* `checked_add`, `checked_sub`, `checked_mul`

**Rule of thumb:**
Never rely on post-arithmetic values for safety unless the arithmetic is checked.

---

## 5) Program authority risks: avoid “signing oracle” behavior

**Example:** `vault-signing-oracle`

Programs often control PDAs that hold value. If an instruction lets any caller redirect value to arbitrary recipients, the program becomes a “confused deputy”.

**Rule of thumb:**
Any instruction that moves funds out of a PDA must enforce:

* who may trigger it (signer + relationship checks)
* where funds may go (recipient constraints)
* how much may move (amount constraints)

---

## Checklist (quick)

Before shipping an instruction, ask:

1. **Authorization**

* Who is allowed to call this?
* Do I require the right signer?
* Is signer tied to state (has_one / address checks)?

2. **Account validation**

* Are all critical accounts validated?
* Are PDAs derived and enforced with seeds/bump?
* Are token accounts validated (mint/authority/owner) when applicable?

3. **CPI safety**

* Is the CPI target pinned?
* Are CPI accounts validated and minimal?
* Do I update state before/after CPI safely?

4. **Math & invariants**

* Are all adds/subs checked?
* Are invariant checks done before mutation?
* Could underflow/overflow bypass logic?

---

## Repo map

* `programs/vault-missing-signer`
* `programs/vault-pda-spoofing`
* `programs/vault-cpi-injection` (+ `payment-legit`, `payment-evil`)
* `programs/vault-unchecked-math`
* `programs/vault-signing-oracle`
