# payment-legit — Legit CPI Payment Collector

## Bug summary

None. This program is intentionally **non-vulnerable** and exists as the trusted CPI target for the CPI-injection example.

## What it does

Implements:

* `collect_payment(amount)`

Behavior:

* Transfers SOL from `payer` → `vault` via the System Program
* Returns `Ok(())` only if the transfer succeeds

## Why it exists in this repo

`vault-cpi-injection` demonstrates that if a vault mints credits based on “payment collected”, it must:

* **pin** the CPI program id to a known good program, and
* validate the CPI account set

This program represents the “known good” CPI target.

## Related example

* `programs/vault-cpi-injection`
