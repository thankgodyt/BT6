Audit Report

## Title
Precision Loss in `normalize_amount` Permanently Locks User Tokens When Transfer Amount Falls Below Decimal Threshold — (File: `near/omni-bridge/src/lib.rs`)

## Summary

When a user initiates a NEAR-to-foreign-chain transfer where `origin_decimals > decimals` and the net transfer amount (amount minus fee) is less than `10^(origin_decimals − decimals)`, `normalize_amount` returns `0` via integer floor division. The subsequent `sign_transfer` call panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because the user's tokens were already accepted and locked by `init_transfer_internal` before `sign_transfer` is ever called, and no public cancel or refund path exists for pending transfers, those tokens are permanently frozen in the bridge.

## Finding Description

`normalize_amount` performs unchecked floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

When `amount < 10^diff_decimals`, the result is `0`. In `sign_transfer`, this normalized value is checked immediately after computation:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [2](#0-1) 

This panic occurs **after** the user's tokens have already been accepted and stored. In `init_transfer_internal`, the transfer message is inserted into `pending_transfers`, the storage balance is deducted, tokens are burned (if deployed) or locked via `lock_tokens_if_needed`, and `U128(0)` is returned — signaling to the NEP-141 token contract that all tokens were consumed (no refund): [3](#0-2) 

`remove_transfer_message` is a private internal function with no public-facing wrapper. It is only reachable through internal callbacks that require either a signed MPC payload or a finalized cross-chain proof — neither of which can ever exist for a transfer that `sign_transfer` refuses to sign: [4](#0-3) 

No minimum-amount guard exists at transfer initiation time in `init_transfer` or `init_transfer_internal` to reject amounts that would normalize to zero before tokens are locked. [5](#0-4) 

## Impact Explanation

This constitutes **permanent freezing of bridged funds** — a concrete critical impact matching the allowed scope. Any user who sends a token amount (net of fee) smaller than `10^(origin_decimals − decimals)` from NEAR to a foreign chain will have their tokens permanently frozen in the bridge. No relayer can ever successfully call `sign_transfer` for that transfer ID; every attempt panics identically. No on-chain path exists for the user to reclaim the locked balance.

## Likelihood Explanation

The condition is reachable by any unprivileged bridge user through a standard `ft_transfer_call`. Tokens bridged between chains with large decimal differences (e.g., a NEAR-native token with 24 decimals registered on an EVM chain with 6 decimals, giving `diff_decimals = 18`) have a minimum transferable unit of `10^18`. A user sending any amount below that threshold — a plausible mistake given that NEAR token balances are displayed in yocto units — triggers the freeze. No special role or privileged access is required.

## Recommendation

1. **Enforce a minimum amount at initiation time**: In `init_transfer_internal`, look up the token's `Decimals` and reject (refund) any transfer whose `amount_without_fee()` is less than `10^(origin_decimals − decimals)`, returning the full amount to the caller per the NEP-141 refund convention.
2. **Add a public `cancel_transfer` function**: Allow the original sender to cancel a pending transfer that has not yet been signed, unlocking the locked tokens and returning them to the user. This also serves as a general safety valve for stuck transfers.
3. **Alternatively**, enforce that `decimals.origin_decimals − decimals.decimals` never exceeds a safe bound at token registration time, or require that the registered `decimals` value always equals `origin_decimals` (no normalization), eliminating the precision-loss class entirely.

## Proof of Concept

**Setup**: Token registered with `origin_decimals = 24`, `decimals = 6` (`diff_decimals = 18`). Minimum transferable unit = `10^18`.

**Steps**:
1. User calls `ft_transfer_call` on the token contract with `amount = 5 × 10^17` (below the minimum unit) and `fee = 0`.
2. Bridge's `ft_on_transfer` → `init_transfer` → `init_transfer_internal` accepts the tokens, stores the `TransferMessage` in `pending_transfers`, locks the tokens via `lock_tokens_if_needed`, and returns `U128(0)` (no refund to the token contract).
3. Relayer calls `sign_transfer(transfer_id, ...)`.
4. Inside `sign_transfer`:
   - `amount_without_fee()` = `5 × 10^17`
   - `normalize_amount(5×10^17, {origin_decimals:24, decimals:6})` = `5×10^17 / 10^18` = **0**
   - `require!(0 > 0, ...)` → **panic: ERR_INVALID_AMOUNT_TO_TRANSFER**
5. Every subsequent relayer call for this `transfer_id` panics identically.
6. `remove_transfer_message` is unreachable: no signed payload exists (MPC signing was never completed), so no callback path can remove the pending transfer.
7. The user's `5 × 10^17` tokens remain permanently locked in the bridge with no recovery path.

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

**File:** near/omni-bridge/src/lib.rs (L523-619)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );

        let required_storage_balance =
            self.required_balance_for_init_transfer_message(transfer_message.clone());

        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));

        // Choose storage payer or whether to yield execution until storage is available
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
            PromiseOrPromiseIndexOrValue::Value(
                self.init_transfer_internal(transfer_message, signer_id),
            )
        } else {
            let promise_index = env::promise_yield_create(
                "init_transfer_resume",
                json!({
                    "transfer_message": transfer_message,
                    "message_storage_account_id": message_storage_account_id,
                    "storage_owner": signer_id,
                })
                .to_string()
                .as_bytes(),
                INIT_TRANSFER_RESUME_GAS,
                GasWeight(0),
                PROMISE_REGISTER_ID,
            );

            let yield_id: CryptoHash = env::read_register(PROMISE_REGISTER_ID)
                .near_expect(BridgeError::ReadPromiseRegister)
                .try_into()
                .near_expect(BridgeError::ReadPromiseYieldId);

            let required_storage_balance = self.add_promise(&message_storage_account_id, &yield_id);

            self.update_storage_balance(
                env::current_account_id(),
                required_storage_balance,
                NearToken::from_yoctonear(0),
            );

            env::log_str(&format!(
                "Yield init transfer until storage is available at {message_storage_account_id}"
            ));

            PromiseOrPromiseIndexOrValue::PromiseIndex(promise_index)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
    }
```

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
