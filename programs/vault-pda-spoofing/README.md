# vault-pda-spoofing — PDA Spoofing (Missing seeds/bump validation)

## Bug summary

The vulnerable withdraw accepts an arbitrary `vault` account without verifying that it is the PDA derived from the expected seeds.

A caller can pass someone else’s vault PDA and withdraw to themselves.

## Vulnerable instruction

* `withdraw_vulnerable`

### Why it’s exploitable

Accounts passed into an instruction are attacker-controlled. If you don’t enforce PDA derivation, you cannot trust that a provided account is *the* intended vault.

## Secure instruction

* `withdraw_secure`

### Why the fix works

Uses Anchor PDA constraints:

* `seeds = [b"vault", authority.key().as_ref()]`
* `bump = vault.bump`

So the vault account must equal the program-derived PDA for that authority.

## Test

The test shows Bob can drain Alice’s vault using the vulnerable withdraw, but the secure withdraw fails for Bob and succeeds for Alice.
