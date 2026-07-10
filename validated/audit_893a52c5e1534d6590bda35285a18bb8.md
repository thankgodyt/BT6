### Title
Safe Deposit Path Bypasses Fee Collection, Causing nBTC Over-Minting - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary
`internal_safe_verify_deposit` always passes the raw `deposit_amount` as the `mint_amount` to `verify_safe_deposit_callback`, with no fee deduction. The regular deposit path (`internal_verify_deposit`) correctly subtracts `deposit_bridge_fee` before minting. This hardcoded assumption — that the safe-deposit mint amount equals the full deposit amount — is only correct when fees are zero, and silently over-mints nBTC whenever `deposit_bridge_fee` is non-zero.

### Finding Description
`internal_verify_deposit` (the standard path) computes the mint amount after deducting fees:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs  lines 52-56
let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
let mint_amount = deposit_amount - deposit_fee;
let (protocol_fee, relayer_fee) = config
    .deposit_bridge_fee
    .get_protocol_and_relayer_fee(deposit_fee);
```

`internal_safe_verify_deposit` (the safe-deposit path) skips this entirely and forwards the raw amount:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs  lines 104-113
} else {
    promise.then(
        Self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
            .verify_safe_deposit_callback(
                recipient_id,
                deposit_amount.into(),   // ← full amount, no fee deduction
                deposit_msg.msg,
                pending_utxo_info,
            ),
    )
}
```

`verify_safe_deposit_callback` then calls `safe_mint(recipient_id, mint_amount, msg)` with that uncorrected value, minting the full deposit amount to the user.

A user controls the `safe_deposit` field inside `DepositMsg`. Because `verify_deposit` hard-rejects any message that carries `safe_deposit` (`require!(deposit_msg.safe_deposit.is_none(), "safe_deposit not supported in verify_deposit")`), a relayer processing such a deposit **must** call `verify_safe_deposit` instead. The relayer cannot route around the safe-deposit path once the user has embedded that field.

### Impact Explanation
Every satoshi of `deposit_bridge_fee` that should be withheld is instead minted as nBTC. Over time this inflates nBTC supply beyond the BTC held by the bridge, breaking the 1:1 backing invariant. This matches the Medium allowed impact: *"harmful smart-contract behavior … including permanent burning below backed supply."* If fee rates are material (e.g. `fee_min = 50 000 sat` as shown in test scaffolding), the per-deposit over-mint is significant and cumulative.

### Likelihood Explanation
Any depositor can embed `safe_deposit` in their `DepositMsg` before sending BTC. The deposit address is derived from the hash of that message, so the field is fully user-controlled. A compliant relayer has no alternative but to call `verify_safe_deposit`; calling `verify_deposit` would panic. No privileged access, leaked key, or operator collusion is required.

### Recommendation
Apply the same fee-deduction logic inside `internal_safe_verify_deposit` before scheduling `verify_safe_deposit_callback`:

```rust
let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
let mint_amount = deposit_amount - deposit_fee;
// pass mint_amount (not deposit_amount) to verify_safe_deposit_callback
```

Alternatively, unify both paths through a single fee-computation helper to prevent future divergence.

### Proof of Concept
1. User constructs `DepositMsg` with a non-empty `safe_deposit` field and sends 0.01 BTC (1 000 000 sat) to the derived deposit address.
2. With `deposit_bridge_fee = { fee_min: 50000, fee_rate: 100, protocol_fee_rate: 9000 }`, the correct mint amount is `1 000 000 − 10 000 = 990 000 sat`.
3. Relayer calls `verify_safe_deposit`; `verify_deposit` would panic on the `safe_deposit.is_none()` guard.
4. `internal_safe_verify_deposit` schedules `verify_safe_deposit_callback` with `mint_amount = 1 000 000` (full amount).
5. `safe_mint` mints 1 000 000 nBTC-satoshis to the user — 10 000 sat more than the bridge is entitled to issue, with zero fee collected. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L52-56)
```rust
            let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
            let mint_amount = deposit_amount - deposit_fee;
            let (protocol_fee, relayer_fee) = config
                .deposit_bridge_fee
                .get_protocol_and_relayer_fee(deposit_fee);
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L97-114)
```rust
        if deposit_amount < config.min_deposit_amount {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_UNAVAILABLE_UTXO_CALL_BACK)
                    .unavailable_utxo_callback(recipient_id, pending_utxo_info),
            )
        } else {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
                    .verify_safe_deposit_callback(
                        recipient_id,
                        deposit_amount.into(),
                        deposit_msg.msg,
                        pending_utxo_info,
                    ),
            )
        }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L127-129)
```rust
        require!(
            deposit_msg.safe_deposit.is_none(),
            "safe_deposit not supported in verify_deposit"
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L409-412)
```rust
        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .safe_mint(recipient_id.clone(), mint_amount, msg)
```
