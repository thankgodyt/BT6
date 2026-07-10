### Title
Untracked nBTC Dust Permanently Locked in Bridge Balance Due to `burn_amount` Offset - (File: contracts/satoshi-bridge/src/api/token_receiver.rs)

### Summary

In the withdrawal flow, `burn_amount` is set to `actual_received_amount + gas_fee` rather than `transfer_amount - withdraw_fee`. The contract explicitly permits `actual_received_amount` to be up to `min_change_amount` less than `transfer_amount - withdraw_fee - gas_fee`. The resulting difference ("dust") remains in the bridge's nBTC balance permanently, is never tracked in `cur_available_protocol_fee`, and cannot be recovered through any existing withdrawal mechanism.

### Finding Description

When a user initiates a withdrawal via `ft_transfer_call`, the bridge receives `amount` nBTC. In `create_btc_pending_info`, `burn_amount` is computed as:

```rust
burn_amount: actual_received_amount + gas_fee,
``` [1](#0-0) 

In `check_withdraw_psbt`, the contract explicitly relaxes validation to allow `actual_received_amount` to be as low as `max_received_amount - config.min_change_amount`:

```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
let min_received_amount = max_received_amount - config.min_change_amount;
require!(
    actual_received_amount >= min_received_amount
        && actual_received_amount <= max_received_amount,
    ...
);
``` [2](#0-1) 

The comment explains this is intentional — the relayer may deduct from the user's output to avoid creating a sub-dust change UTXO: [3](#0-2) 

After the `burn` call in `verify_withdraw_burn_promise`, the nbtc contract destroys `burn_amount` and transfers `relayer_fee` from the bridge's balance: [4](#0-3) 

The bridge's residual nBTC balance after the burn is:

```
amount - burn_amount - relayer_fee
= (withdraw_fee - relayer_fee) + (max_received_amount - actual_received_amount)
= protocol_fee + dust
```

Only `protocol_fee` is tracked in `cur_available_protocol_fee`: [5](#0-4) 

The `dust = max_received_amount - actual_received_amount` (up to `min_change_amount` per withdrawal) is never added to `cur_available_protocol_fee` and never burned. The only withdrawal mechanism for the bridge's nBTC balance is `withdraw_protocol_fee`, which is bounded by `cur_available_protocol_fee`: [6](#0-5) 

There is no other function that can drain the bridge's nBTC balance. The dust is permanently locked.

### Impact Explanation

After each withdrawal where `actual_received_amount < max_received_amount`, the bridge's nBTC balance exceeds `cur_available_protocol_fee + cur_reserved_protocol_fee` by the dust amount. This invariant violation accumulates silently across all withdrawals. The locked nBTC is backed by BTC (the change UTXOs returned to the bridge), so there is no supply/backing mismatch, but the DAO permanently loses access to the accumulated dust. This is a publicly reachable stuck-state in the production bridge path.

**Severity: Low** — stuck-state invariant violation without direct theft; the dust is BTC-backed but permanently irrecoverable.

### Likelihood Explanation

This occurs in any withdrawal where the change output would fall below `min_change_amount`, which is a normal operational scenario (e.g., when a UTXO is nearly fully consumed). Any user performing a withdrawal can trigger this path by constructing a PSBT where `actual_received_amount < max_received_amount`. No special privileges are required.

### Recommendation

Either:
1. Set `burn_amount = transfer_amount - withdraw_fee` so all non-fee nBTC is always burned, regardless of the actual BTC output amount; or
2. Track the dust explicitly: `cur_available_protocol_fee += max_received_amount - actual_received_amount` in `create_btc_pending_info` or in `verify_withdraw_burn_callback`.

Option 1 is simpler and mirrors the fix recommended in the PA1D report — burn based on the full entitled amount rather than the offset actual amount.

### Proof of Concept

1. Alice has 200,000 nBTC. `withdraw_fee = 10,000`, `min_change_amount = 5,000`, `min_btc_gas_fee = 9,000`.
2. Alice calls `ft_transfer_call` with `amount = 200,000`, constructing a PSBT where `actual_received_amount = 181,000` (instead of `max_received_amount = 181,000`... let's say `actual_received_amount = 176,000` to absorb dust into change).
3. `burn_amount = 176,000 + 9,000 = 185,000`.
4. Bridge burns 185,000 nBTC, transfers relayer fee from bridge balance.
5. Bridge's residual nBTC = `200,000 - 185,000 - relayer_fee`. The `protocol_fee` portion is tracked; the `5,000` dust is not.
6. `withdraw_protocol_fee` can only access `cur_available_protocol_fee`; the 5,000 dust is permanently locked in the bridge's nBTC balance with no recovery path.

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L110-110)
```rust
            burn_amount: actual_received_amount + gas_fee,
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L239-250)
```rust
        // When constructing the withdraw transaction, if the change is less than min_change_amount (dust),
        // the caller may deduct a portion from the user's output to make the change amount meet min_change_amount.
        // Therefore, the contract relaxes the validation.
        let max_received_amount = amount - withdraw_fee - gas_fee;
        let min_received_amount = max_received_amount - config.min_change_amount;
        require!(
            actual_received_amount >= min_received_amount
                && actual_received_amount <= max_received_amount,
            format!(
                "The user's output amount ({}) is out of the valid range ({}, {})",
                actual_received_amount, min_received_amount, max_received_amount
            )
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L17-24)
```rust
        ext_nbtc::ext(config.nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_BURN_CALL)
            .burn(
                btc_pending_info.account_id.clone(),
                btc_pending_info.burn_amount.into(),
                env::signer_account_id(),
                relayer_fee.into(),
            )
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L135-138)
```rust
            if protocol_fee.0 > 0 {
                self.data_mut().acc_collected_protocol_fee += protocol_fee.0;
                self.data_mut().cur_available_protocol_fee += protocol_fee.0;
            }
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L23-28)
```rust
        let total_protocol_fee = self.data().cur_available_protocol_fee;
        let amount = amount.map_or(total_protocol_fee, |v| v.0);
        require!(amount > 0 && amount <= total_protocol_fee, "Invalid amount");
        self.data_mut().cur_available_protocol_fee -= amount;
        self.data_mut().acc_claimed_protocol_fee += amount;
        self.internal_withdraw_protocol_fee(amount)
```
