# vault-missing-signer — Missing Signer / Authority Check

## Bug summary

The vulnerable instruction checks that `current_authority.key() == vault.authority` but does **not** require `current_authority` to be a **Signer**.

An attacker can pass the real authority’s public key as a normal account (non-signer) and still pass the check, then take over the vault.

## Vulnerable instruction

* `set_authority_vulnerable`

### Why it’s exploitable

On Solana, a public key match is not authorization. Authorization requires a **signature** (or a trusted PDA signing rule) plus correct relationships between accounts.

## Secure instruction

* `set_authority_secure`

### Why the fix works

* Requires `authority: Signer`
* Uses `#[account(has_one = authority)]` to bind state authority to the signer

## Test

The test shows Bob (attacker) can call the vulnerable method and steal authority, but the secure method rejects him and only allows the real authority.
