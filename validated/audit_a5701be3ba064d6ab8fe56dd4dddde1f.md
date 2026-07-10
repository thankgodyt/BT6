### Title
Missing Ownership Check in `withdraw_rbf` Allows Attacker to Redirect Victim's BTC Withdrawal - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The `withdraw_rbf` function in the satoshi-bridge contract does not verify that the caller owns the original pending withdrawal transaction. An unprivileged attacker can call `withdraw_rbf` with a victim's `original_btc_pending_verify_id` and attacker-controlled `output`, causing the bridge to build and MPC-sign a replacement BTC transaction that redirects the victim's funds to the attacker's Bitcoin address.

### Finding Description

`withdraw_rbf` is the public, permissionless entry point for users to bump the gas fee on their own pending BTC withdrawal via Replace-By-Fee. The function captures the caller as `account_id` but never checks that this caller is the owner of the referenced `original_btc_pending_verify_id`:

```rust
// contracts/satoshi-bridge/src/api/bridge.