# vault-cpi-injection — CPI Program Injection (Unpinned CPI target)

## Bug summary

The vulnerable deposit performs a CPI to a “payment program” account provided by the user. If that program is malicious, it can return `Ok(())` without collecting payment.

The vault credits the user anyway, enabling withdrawal of real funds deposited by others.

## Programs involved

* `vault-cpi-injection` (the vulnerable/secure example)
* `payment-legit` (actually transfers SOL payer → vault)
* `payment-evil` (does nothing, returns Ok)

## Vulnerable instruction

* `deposit_vulnerable`

### Why it’s exploitable

If the caller controls the CPI target program id, they control what “success” means. A malicious program can lie about side effects.

## Secure instruction

* `deposit_secure`

### Why the fix works

Pins the CPI target:

* `payment_program: Program<'info, payment_legit::program::PaymentLegit>`

Anchor enforces the passed program account matches the expected program id.

## Test

The test shows:

1. Alice deposits via the legit payment program (vault balance increases)
2. Bob deposits via evil program (vault balance does not increase) but Bob still gets credits
3. secure deposit rejects the evil program id
4. Bob withdraws real SOL using fake credits (demonstrating the impact)
