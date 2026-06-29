### Title
TOCTOU Race Between `fast_fin_transfer` and `fin_transfer_callback` Enables Double-Spending of Bridged Funds — (File: near/omni-bridge/src/lib.rs)

---

### Summary

`fast_fin_transfer` (NEAR recipient path) reads `finalised_transfers` to guard against double-finalization but does **not** write to `fast_transfers` before returning. The actual state write occurs in `fast_fin_transfer_to_near_callback`, which executes in a future NEAR transaction. During the window between the guard check and the state write, `fin_transfer_callback` can execute, find no fast-transfer record, and send tokens to the original recipient. When `fast_fin_transfer_to_near_callback` subsequently executes, it also sends tokens to the same recipient, producing a double-spend of bridged funds.

---

### Finding Description

**Root cause — missing re-check in the callback:**

In `fast_fin_transfer` (NEAR recipient branch), the only guard is:

```rust
// near/omni-bridge/src/lib.rs  line 778-780
if self.is_unified_transfer_finalised(&fast_fin_transfer_msg.transfer_id) {
    env::panic_str(BridgeError::TransferAlreadyFinalised.to_string().as_str());
}
``` [1](#0-0) 

After this check, for a NEAR recipient the function creates an async promise chain and **returns without writing anything to `fast_transfers`**:

```rust
// lines 812-827
Self::check_or_pay_ft_storage(&deposit_action, ...)
    .then(
        Self::ext(env::current_account_id())
            .fast_fin_transfer_to_near_callback(&fast_transfer, signer_id, relayer),
    )
    .into()
``` [2](#0-1) 

The actual state write (`add_fast_transfer`) happens only inside the callback:

```rust
// lines 854-856
let required_balance = self
    .add_fast_transfer(fast_transfer, relayer_id, storage_payer.clone())
    .saturating_add(ONE_YOCTO);
``` [3](#0-2) 

`fast_fin_transfer_to_near_callback` contains **no re-check** of `is_unified_transfer_finalised`. Its only guard is `add_fast_transfer`'s uniqueness check on `fast_transfers`, which is a different map from `finalised_transfers`. [4](#0-3) 

**Concurrent path — `process_fin_transfer_to_near`:**

`fin_transfer_callback` → `process_fin_transfer_to_near` reads `fast_transfers` to decide the recipient:

```rust
// lines 1879, 1888-1901
let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());
let (recipient, msg, fee_recipient) = match fast_transfer_status {
    Some(status) => { /* redirect to relayer */ }
    None => (recipient, transfer_message.msg.clone(), predecessor_account_id.clone()),
};
``` [5](#0-4) 

If `fast_transfers` is still empty (because `fast_fin_transfer_to_near_callback` has not yet executed), `process_fin_transfer_to_near` sends tokens to the **original recipient** and marks the transfer finalized in `finalised_transfers`. [6](#0-5) 

**Race window (NEAR async model):**

| Block | Event |
|-------|-------|
| B1 | Trusted relayer calls `fast_fin_transfer` → guard passes, promise chain created, **`fast_transfers` still empty** |
| B2 | Another relayer calls `fin_transfer` |
| B3 | `fin_transfer_callback` → `process_fin_transfer_to_near` → `fast_transfers` empty → **sends tokens to recipient (first delivery)** → writes to `finalised_transfers` |
| B4 | `fast_fin_transfer_to_near_callback` → `add_fast_transfer` succeeds (no uniqueness conflict in `fast_transfers`) → **sends tokens to recipient again (second delivery)** |

The two maps (`finalised_transfers` and `fast_transfers`) are checked and written independently across different transactions, creating the unsynchronized window. [7](#0-6) [8](#0-7) 

---

### Impact Explanation

**Double-spending of bridged funds.** The recipient receives tokens twice:

- **First delivery**: `process_fin_transfer_to_near` unlocks/mints tokens from the bridge's locked supply and sends them to the recipient.
- **Second delivery**: `fast_fin_transfer_to_near_callback` mints/transfers the relayer's pre-funded tokens to the same recipient.

For deployed (bridge-minted

### Citations

**File:** near/omni-bridge/src/lib.rs (L778-780)
```rust
        if self.is_unified_transfer_finalised(&fast_fin_transfer_msg.transfer_id) {
            env::panic_str(BridgeError::TransferAlreadyFinalised.to_string().as_str());
        }
```

**File:** near/omni-bridge/src/lib.rs (L812-827)
```rust
            Self::check_or_pay_ft_storage(
                &deposit_action,
                &mut NearToken::from_yoctonear(storage_deposit_amount),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(
                        FAST_TRANSFER_CALLBACK_GAS.saturating_add(FT_TRANSFER_CALL_GAS),
                    )
                    .fast_fin_transfer_to_near_callback(
                        &fast_transfer,
                        signer_id,
                        fast_fin_transfer_msg.relayer,
                    ),
            )
            .into()
```

**File:** near/omni-bridge/src/lib.rs (L838-893)
```rust
    #[private]
    pub fn fast_fin_transfer_to_near_callback(
        &mut self,
        #[serializer(borsh)] fast_transfer: &FastTransfer,
        #[serializer(borsh)] storage_payer: AccountId,
        #[serializer(borsh)] relayer_id: AccountId,
    ) -> Promise {
        require!(
            Self::check_storage_balance_result(0),
            BridgeError::StorageRecipientOmitted.as_ref()
        );

        let OmniAddress::Near(recipient) = fast_transfer.recipient.clone() else {
            env::panic_str(BridgeError::InvalidState.to_string().as_str())
        };

        let required_balance = self
            .add_fast_transfer(fast_transfer, relayer_id, storage_payer.clone())
            .saturating_add(ONE_YOCTO);

        self.update_storage_balance(
            storage_payer,
            required_balance,
            NearToken::from_yoctonear(0),
        );

        env::log_str(
            &OmniBridgeEvent::FastTransferEvent {
                fast_transfer: fast_transfer.clone(),
                new_transfer_id: None,
            }
            .to_log_string(),
        );

        let amount_without_fee = U128(
            fast_transfer
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
        );
        self.send_tokens(
            fast_transfer.token_id.clone(),
            recipient,
            amount_without_fee,
            &fast_transfer.msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(RESOLVE_FAST_TRANSFER_GAS)
                .resolve_fast_transfer(
                    &fast_transfer.token_id,
                    &fast_transfer.id(),
                    amount_without_fee,
                    !fast_transfer.msg.is_empty(),
                ),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1875-1878)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
```

**File:** near/omni-bridge/src/lib.rs (L1879-1901)
```rust
        let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());

        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];

        // If fast transfer happened, change recipient and fee recipient to the relayer that executed fast transfer
        let (recipient, msg, fee_recipient) = match fast_transfer_status {
            Some(status) => {
                require!(
                    !status.finalised,
                    BridgeError::FastTransferAlreadyFinalised.as_ref()
                );
                self.remove_fast_transfer(&fast_transfer.id());
                (status.relayer.clone(), String::new(), status.relayer)
            }
            None => (
                recipient,
                transfer_message.msg.clone(),
                predecessor_account_id.clone(),
            ),
```

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```

**File:** near/omni-bridge/src/lib.rs (L2246-2268)
```rust
    fn add_fast_transfer(
        &mut self,
        fast_transfer: &FastTransfer,
        relayer: AccountId,
        storage_owner: AccountId,
    ) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.fast_transfers
                .insert(
                    &fast_transfer.id(),
                    &FastTransferStatusStorage::V0(FastTransferStatus {
                        relayer,
                        storage_owner,
                        finalised: false,
                    }),
                )
                .is_none(),
            BridgeError::FastTransferAlreadyPerformed.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```
