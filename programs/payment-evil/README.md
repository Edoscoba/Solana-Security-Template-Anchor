# payment-evil — Malicious CPI Target (Injection Demo)

## Bug summary

This program is intentionally malicious. It implements the same CPI interface as `payment-legit` but lies about side effects.

## What it does

Implements:

* `collect_payment(amount)`

Behavior:

* Performs **no transfer**
* Still returns `Ok(())`

## Why it matters

If a vault allows the caller to supply the CPI target program id (unpinned CPI), an attacker can:

1. point CPI to `payment-evil`
2. mint credits without paying
3. withdraw real value deposited by honest users

## Related example

* `programs/vault-cpi-injection`
