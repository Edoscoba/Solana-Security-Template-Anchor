# vault-unchecked-math — Wrapping Math / Underflow breaks invariants

## Bug summary

The vulnerable withdraw uses `wrapping_sub` and then performs meaningless checks (e.g., `>= 0` on `u64`). When credits are insufficient, the subtraction underflows and becomes a huge number.

Result: a user with 0 credits can withdraw anyway and even end up with enormous remaining credits.

## Vulnerable instruction

* `withdraw_vulnerable`

### Why it’s exploitable

Unsigned underflow turns “negative” into a giant integer. If your check is based on the post-underflow value, the check becomes bypassable.

## Secure instruction

* `withdraw_secure`

### Why the fix works

* Check `credits >= amount` and `vault.balance >= amount` first
* Use `checked_sub` to prevent underflow

## Test

The test shows secure withdraw blocks Bob, but vulnerable withdraw lets Bob drain the vault and results in Bob’s credits becoming huge.
