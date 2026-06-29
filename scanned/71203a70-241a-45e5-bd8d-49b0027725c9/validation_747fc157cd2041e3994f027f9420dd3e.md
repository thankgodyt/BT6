### Title
Inverted Refund Condition in `is_refund_required` Causes Double-Spend and Replay on UTXO `ft_transfer_call` Finalization - (File: `near/omni-bridge/src/lib.rs`)

### Summary
`Contract::is_refund_required` contains inverted boolean logic: it returns `true` (refund required) when the downstream `ft_on_transfer` returned `0` (meaning all tokens were successfully consumed), and `false` (no refund) when the receiver returned a non-zero unused amount. This is the exact inversion of the correct NEP-141 semantics. The consequence is that every successful UTXO-to-NEAR `ft_transfer_call` finalization simultaneously delivers tokens to the recipient **and** triggers a full token refund to the UTXO connector, while also erasing the finalization record — enabling replay.

### Finding Description

In `near/omni-bridge/src/lib.rs`, `is_refund_required` reads the promise result of the inner `ft_transfer_call` (the call from the bridge to the NEAR recipient):

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => {
                if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                    // Normal case: refund if the used token amount is zero
                    amount.0 == 0   // ← INVERTED
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    } else {
        false
    }
}
```

Under NEP-141, `ft_on_transfer` on the recipient returns the **unused** (to-be-refunded) token amount:
- Returns `0` → all tokens consumed, **no refund needed**
- Returns `N > 0` → N tokens unused, **refund N tokens**

The code checks `amount.0 == 0`, which evaluates to `true` precisely when the transfer **succeeded** (receiver used all tokens). The comment even contradicts the code: it says "refund if the **used** token amount is zero," but `amount` is the **refund** amount, not the used amount.

`resolve_utxo_fin_transfer` acts on this result:

```rust
pub fn resolve_utxo_fin_transfer(...) -> U128 {
    let is_ft_transfer_call = !utxo_fin_transfer_msg.msg.is_empty();
    if Self::is_refund_required(is_ft_transfer_call) {
        self.remove_fin_utxo_transfer(          // ← erases finalization record
            &utxo_fin_transfer_msg.get_transfer_id(origin_chain),
            storage_owner,
        );
        amount                                  // ← returns full amount as refund
    } else {
        // log event
        U128(0)
    }
}
```

When `is_refund_required` incorrectly returns `true` on success:
1. `remove_fin_utxo_transfer` deletes the finalization record from `finalised_utxo_transfers`.
2. The function returns `amount` (the full bridged amount) as the `ft_on_transfer` return value.
3. The outer token contract's `ft_resolve_transfer` interprets this as "all tokens unused" and refunds the full amount to the UTXO connector.

The call chain is: `utxo_fin_transfer_to_near_callback` → `send_tokens` (inner `ft_transfer_call`) → `resolve_utxo_fin_transfer`. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

**Critical.** For every UTXO-to-NEAR transfer that includes a message (triggering `ft_transfer_call`):

1. **Double-spend**: The recipient receives the bridged tokens (inner `ft_transfer_call` succeeds), and the UTXO connector simultaneously receives a full refund of those same tokens from the outer token contract's `ft_resolve_transfer`. Tokens are created out of thin air on the NEAR side.
2. **Replay / re-finalization**: `remove_fin_utxo_transfer` deletes the entry from `finalised_utxo_transfers`. The same UTXO proof can be submitted again to `utxo_fin_transfer`, passing the "already finalised" guard, and the entire flow repeats — unlimited minting from a single UTXO.

The inverse case (receiver returns non-zero, i.e., transfer failed) causes permanent token loss: `is_refund_required` returns `false`, no refund is issued, and the finalization record is kept, permanently locking the tokens. [4](#0-3) [5](#0-4) 

### Likelihood Explanation

**High.** The trigger condition is a standard, successful UTXO-to-NEAR `ft_transfer_call` finalization — the normal happy path. Any NEAR recipient contract whose `ft_on_transfer` returns `0` (the correct NEP-141 success response) activates the bug. An attacker deploys a recipient contract that returns `0`, submits a valid UTXO proof, and the double-spend occurs automatically. No privileged access, no key compromise, and no race condition is required. [6](#0-5) 

### Recommendation

Invert the condition in `is_refund_required`. The refund amount returned by `ft_on_transfer` is the **unused** token amount; a refund is required when this value is **non-zero**:

```rust
// Correct: refund is required when the receiver returned unused tokens (amount > 0)
amount.0 != 0
```

Also update the misleading comment to clarify that `amount` is the refund amount (unused tokens), not the used amount. [7](#0-6) 

### Proof of Concept

1. Attacker deploys a NEAR contract `attacker.near` whose `ft_on_transfer` always returns `"0"` (NEP-141 success).
2. Attacker initiates a Bitcoin transfer to `attacker.near` with a non-empty `msg` field (so `is_ft_transfer_call = true`).
3. Attacker submits the UTXO proof to `utxo_fin_transfer` on the bridge. `add_fin_utxo_transfer` records the transfer as finalised.
4. `utxo_fin_transfer_to_near_callback` calls `send_tokens` → inner `ft_transfer_call` → `attacker.near::ft_on_transfer` returns `"0"`.
5. `resolve_utxo_fin_transfer` is called. `is_refund_required` reads the promise result `"0"`, evaluates `0 == 0 → true`, calls `remove_fin_utxo_transfer` (deletes finalization record), and returns `amount`.
6. The outer token contract's `ft_resolve_transfer` sees return value = `amount` and refunds `amount` tokens to the UTXO connector. `attacker.near` already holds the tokens from step 4.
7. Because the finalization record was deleted in step 5, the attacker resubmits the same UTXO proof and repeats from step 3 — unlimited minting. [1](#0-0) [2](#0-1)

### Citations

**File:** near/omni-bridge/src/lib.rs (L975-1012)
```rust
    #[private]
    pub fn utxo_fin_transfer_to_near_callback(
        &mut self,
        token_id: AccountId,
        recipient: AccountId,
        amount: U128,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
        origin_chain: ChainKind,
        storage_owner: &AccountId,
    ) -> PromiseOrValue<U128> {
        if !Self::check_storage_balance_result(0) {
            env::log_str(BridgeError::StorageRecipientOmitted.to_string().as_str());
            self.remove_fin_utxo_transfer(
                &utxo_fin_transfer_msg.get_transfer_id(origin_chain),
                storage_owner,
            );
            return PromiseOrValue::Value(amount);
        }

        self.send_tokens(
            token_id.clone(),
            recipient,
            amount,
            &utxo_fin_transfer_msg.msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(RESOLVE_UTXO_FIN_TRANSFER_GAS)
                .resolve_utxo_fin_transfer(
                    token_id,
                    amount,
                    utxo_fin_transfer_msg,
                    origin_chain,
                    storage_owner,
                ),
        )
        .into()
    }
```

**File:** near/omni-bridge/src/lib.rs (L1014-1044)
```rust
    #[allow(clippy::needless_pass_by_value)]
    #[private]
    pub fn resolve_utxo_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
        origin_chain: ChainKind,
        storage_owner: &AccountId,
    ) -> U128 {
        let is_ft_transfer_call = !utxo_fin_transfer_msg.msg.is_empty();
        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fin_utxo_transfer(
                &utxo_fin_transfer_msg.get_transfer_id(origin_chain),
                storage_owner,
            );
            amount
        } else {
            env::log_str(
                &OmniBridgeEvent::UtxoTransferEvent {
                    token_id,
                    amount,
                    utxo_transfer_message: utxo_fin_transfer_msg,
                    new_transfer_id: None,
                }
                .to_log_string(),
            );

            U128(0)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1784-1804)
```rust
    fn is_refund_required(is_ft_transfer_call: bool) -> bool {
        if is_ft_transfer_call {
            match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
                Ok(value) => {
                    if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                        // Normal case: refund if the used token amount is zero
                        // The amount can be zero if the `ft_on_transfer` in the receiver contract returns an amount instead of `0`, or if it panics.
                        amount.0 == 0
                    } else {
                        // Unexpected case: don't refund
                        false
                    }
                }
                // Unexpected case: don't refund
                Err(_) => false,
            }
        } else {
            // Not ft_transfer_call: don't refund
            false
        }
    }
```
