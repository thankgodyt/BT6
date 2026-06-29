Audit Report

## Title
Permanent Freezing of User Funds via `normalize_amount` Returning Zero in `sign_transfer` — (File: `near/omni-bridge/src/lib.rs`)

## Summary

When a user initiates a bridge transfer with a token amount smaller than `10^(origin_decimals - decimals)`, `normalize_amount` returns zero via floor division. `sign_transfer` then hard-panics with `InvalidAmountToTransfer` before reaching the MPC signer. Because tokens are already locked/burned in `init_transfer` and no user-accessible cancel or refund path exists, the funds are permanently frozen in the bridge contract.

## Finding Description

**Root cause — `normalize_amount` floor division:** [1](#0-0) 

When `origin_decimals > decimals` (e.g., 24 vs 18, a 6-decimal gap), any `amount < 10^6` raw units produces `0`.

**`sign_transfer` panics on zero before MPC call:** [2](#0-1) 

The panic occurs before `ext_signer::ext(...).sign(...)` is called, so `sign_transfer_callback` is never reached. [3](#0-2) 

**`sign_transfer_callback` only removes the transfer on MPC success:** [4](#0-3) 

Since the callback is never invoked, `remove_transfer_message` is never called and the `TransferMessage` stays in `pending_transfers` indefinitely.

**`init_transfer` has no minimum-amount guard:** [5](#0-4) 

The only check is `fee < amount`. There is no pre-lock validation that `normalize_amount(amount - fee, decimals) > 0`. Tokens are locked/burned before `sign_transfer` is ever called.

Every subsequent relayer call to `sign_transfer` for the same `transfer_id` will panic identically (the stored amount is fixed), making the freeze permanent without DAO-level intervention.

## Impact Explanation

This is a **permanent freezing of bridged funds** — a Critical impact explicitly listed in the allowed scope. The user's NEP-141 tokens are transferred to the bridge contract in `init_transfer` (locked or burned via `LockAction`) and can never be recovered through any user-accessible on-chain path. The bridge accounting is permanently mis-stated: tokens are debited from the user but never credited on the destination chain.

## Likelihood Explanation

Any token registered with `origin_decimals > decimals` is affected. The most common real-world case is a NEAR-native token with 24 decimals bridged to an EVM chain where it is registered with 18 decimals (6-decimal gap), meaning any transfer of fewer than `1_000_000` raw units triggers the freeze. The `ft_transfer_call` entry point is fully permissionless — any token holder can trigger this unintentionally by sending a "dust" amount. The condition is deterministic and repeatable: every relayer retry for the same `transfer_id` will panic.

## Recommendation

Add a normalized-amount guard inside `init_transfer`, **before** tokens are locked, so the transfer is rejected while the user can still recover their funds:

```rust
let normalized = Self::normalize_amount(
    amount.0.saturating_sub(init_transfer_msg.fee.0),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the `require!(amount_to_transfer > 0, ...)` check already present in `sign_transfer` but places it at the correct point in the flow — before state is mutated and tokens are locked. [6](#0-5) 

## Proof of Concept

1. Admin registers a token with `origin_decimals = 24`, `decimals = 18` (6-decimal gap).
2. User calls `ft_transfer_call` transferring `500_000` raw units with a valid `InitTransferMsg` targeting an EVM chain.
3. `init_transfer` succeeds — tokens are locked, `TransferMessage` stored in `pending_transfers` (only guard `fee < amount` passes). [5](#0-4) 
4. Trusted relayer calls `sign_transfer(transfer_id, ...)`.
5. `normalize_amount(500_000 - fee, Decimals { origin_decimals: 24, decimals: 18 })` → `500_000 / 1_000_000 = 0`. [1](#0-0) 
6. `require!(0 > 0, InvalidAmountToTransfer)` panics — transaction reverts, no state change. [6](#0-5) 
7. Steps 4–6 repeat forever; `500_000` raw units are permanently locked in the bridge with no user-accessible recovery path.

A local unit test can reproduce this by constructing a `TransferMessage` with `amount = 500_000`, registering `Decimals { origin_decimals: 24, decimals: 18 }`, and asserting that `sign_transfer` panics while the transfer remains in storage.

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-485)
```rust
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L508-521)
```rust
        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_TRANSFER_CALLBACK_GAS)
                    .sign_transfer_callback(transfer_payload, &transfer_message.fee),
            )
    }
```

**File:** near/omni-bridge/src/lib.rs (L554-557)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
