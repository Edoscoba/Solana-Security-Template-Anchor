# vault-signing-oracle — “Signing Oracle” / Misused program authority

## Bug summary

The vulnerable withdraw allows the caller to choose an arbitrary `recipient`, while the program moves lamports out of a program-owned vault PDA.

This is a classic “signing oracle / confused deputy”: the program’s authority over the vault is used to authorize actions the developer did not intend.

## Vulnerable instruction

* `withdraw_vulnerable`

### Why it’s exploitable

Program-owned accounts (PDAs) can only be spent from by the program. If the program doesn’t enforce *who* may withdraw and *where* funds may go, any caller can drain it.

## Secure instruction

* `withdraw_secure`

### Why the fix works

* Requires `authority: Signer`
* Enforces `recipient == authority` so funds cannot be redirected

## Test

The test shows Bob drains the vault via the vulnerable withdraw, while the secure withdraw rejects Bob and succeeds for Alice.
