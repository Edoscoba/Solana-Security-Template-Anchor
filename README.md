# Solana Security Template — Anchor (with tests)

Educational repository of **deliberately vulnerable** Solana programs paired with **secure** alternatives, designed to teach practical security patterns in Anchor.

> ⚠️ **Warning:** These examples contain intentionally vulnerable instructions.
> Use for learning and local testing only. Do not deploy vulnerable variants to mainnet.

## What’s included

Each example contains:

* a **vulnerable instruction**
* a **secure version** of the same instruction
* inline comments explaining the bug + fix
* a test demonstrating exploitation + prevention

## Quick navigation

* Deep dive: `docs/deep-dive.md`
* Example 1: `programs/vault-missing-signer`
* Example 2: `programs/vault-pda-spoofing`
* Example 3: `programs/vault-cpi-injection` (helpers: `programs/payment-legit`, `programs/payment-evil`)
* Example 4: `programs/vault-unchecked-math`
* Example 5: `programs/vault-signing-oracle`


## Examples (5 programs)

1. **Missing Signer / Authority Check**
   `programs/vault-missing-signer`

   * Vulnerable: pubkey equality check without requiring signer
   * Secure: `Signer` + `has_one` constraint

2. **PDA Spoofing (Missing seeds/bump validation)**
   `programs/vault-pda-spoofing`

   * Vulnerable: accepts arbitrary vault account (no PDA constraint)
   * Secure: `seeds` + `bump` enforced

3. **CPI Program Injection (Unpinned CPI target)**
   `programs/vault-cpi-injection` (+ helper programs `payment-legit`, `payment-evil`)

   * Vulnerable: user supplies CPI program id → fake “payment collected”
   * Secure: pins CPI target with `Program<PaymentLegit>`

4. **Unchecked / Wrapping Math (Invariant break)**
   `programs/vault-unchecked-math`

   * Vulnerable: uses wrapping math → underflow turns into huge number
   * Secure: `>=` checks + `checked_sub`

5. **PDA Signing Oracle (Misuse of program authority)**
   `programs/vault-signing-oracle`

   * Vulnerable: program moves lamports to attacker-chosen recipient
   * Secure: requires authority signer + recipient constraint

## Deep dive

See: `docs/deep-dive.md`

## Running locally

```bash
yarn install
anchor test
```

## License

MIT
