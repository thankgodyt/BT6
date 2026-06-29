Audit Report

## Title
Replay Guard Deleted on Failed `ft_transfer_call`, Enabling Double-Spend via Proof Re-submission — (`near/omni-bridge/src/lib.rs`)

## Summary
When a finalized inbound transfer includes a non-empty `msg`, `fin_transfer_send_tokens_callback` calls `remove_fin_transfer` upon `ft_on_transfer` rejection, permanently deleting the `transfer_id` from `finalised_transfers`. This is the contract's sole replay barrier. With the guard gone, the identical proof can be re-submitted through `fin_transfer`, passing `add_fin_transfer` without error and minting or releasing tokens a second time against a single source-chain lock.

## Finding Description

**Verified call chain:**

`fin_transfer` → `fin_transfer_callback` → `process_fin_transfer_to_near` → `add_fin_transfer` (inserts `transfer_id`) + `send_tokens` (non-empty `msg` → `ft_transfer_call` or `mint`-with-msg) → `.then(fin_transfer_send_tokens_callback)`

Inside `fin_transfer_send_tokens_callback` (L1702–1718), when `is_refund_required` returns `true`:

```rust
if Self::is_refund_required(is_ft_transfer_call) {
    self.burn_tokens_if_needed(...);
    self.revert_lock_actions(&lock_actions);
    self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner); // ← deletes replay guard
    env::log_str(&OmniBridgeEvent::FailedFinTransferEvent { ... }.to_log_string());
}
``` [1](#0-0) 

`is_refund_required` returns `true` when `is_ft_transfer_call == true` and the promise result deserializes to `U128(0)` (i.e., `ft_on_transfer` returned the full amount, signaling rejection): [2](#0-1) 

`add_fin_transfer` panics with `TransferAlreadyFinalised` **only if the entry is present**. After `remove_fin_transfer` deletes it, a second `fin_transfer` call with the same proof inserts the same `transfer_id` again without error: [3](#0-2) 

`send_tokens` uses `ft_transfer_call` for non-deployed tokens with non-empty `msg`, and `mint(..., Some(msg))` for deployed tokens — both paths produce a `U128(0)` promise result when the recipient rejects all tokens: [4](#0-3) 

The `msg` field is taken verbatim from `init_transfer.msg` in the proof, which the attacker sets when initiating the cross-chain transfer on the source chain: [5](#0-4) 

## Impact Explanation

This is a **critical double-spend**:

- **Deployed (minted) tokens:** Attempt 1 mints tokens → malicious `ft_on_transfer` rejects → `burn_tokens_if_needed` burns them → `remove_fin_transfer` clears the guard. Attempt 2 (same proof) mints tokens again → malicious contract accepts → attacker holds tokens. One lock on the source chain, two mint events on NEAR.
- **Non-deployed (locked) tokens:** Attempt 1 sends tokens via `ft_transfer_call` → recipient rejects → tokens returned to bridge → guard cleared. Attempt 2 sends tokens again → recipient accepts → bridge releases the same locked tokens twice.

This directly matches the allowed critical impact: *"Stealing, loss, double-spending, or unauthorized minting of bridged funds."*

## Likelihood Explanation

The attacker needs only to:
1. Deploy a stateful NEAR contract whose `ft_on_transfer` rejects on the first call and accepts on the second.
2. Initiate a cross-chain transfer from the source chain with that contract as recipient and any non-empty string as `msg`.
3. Wait for a legitimate relayer to submit the proof (standard behavior). After `FailedFinTransferEvent` is emitted, the intended retry mechanism causes a relayer to re-submit the same proof automatically.

The `#[trusted_relayer]` gate on `fin_transfer` does not block the attack: the attacker controls only the recipient contract, not the relayer. Both submissions are performed by a legitimate relayer. [6](#0-5) 

## Recommendation

**Do not remove `transfer_id` from `finalised_transfers` on failure.** The entry must be permanent — it is the only replay barrier. Recommended alternatives:

- On `ft_on_transfer` rejection, record the failed transfer in a separate `failed_transfers` map keyed by `transfer_id`, allowing the original recipient (or governance) to redirect delivery without re-verifying the proof.
- Keep the `finalised_transfers` entry and introduce a separate `pending_delivery` map for retry logic, so replay protection is never weakened.

## Proof of Concept

```rust
// Malicious recipient contract
static mut CALL_COUNT: u32 = 0;

#[near_bindgen]
impl MaliciousReceiver {
    pub fn ft_on_transfer(&mut self, _sender: AccountId, amount: U128, _msg: String) -> U128 {
        unsafe {
            CALL_COUNT += 1;
            if CALL_COUNT == 1 {
                amount   // reject all → ft_resolve_transfer returns U128(0)
            } else {
                U128(0)  // accept all on second call
            }
        }
    }
}
```

**Localnet sequence:**
1. Deploy bridge + bridge token factory + malicious receiver on localnet.
2. Initiate source-chain transfer with `msg = "attack"` and malicious receiver as recipient.
3. Submit proof via `fin_transfer` → observe `FailedFinTransferEvent` in logs.
4. Assert `is_transfer_finalised(transfer_id) == false` (guard removed by `remove_fin_transfer`).
5. Re-submit identical proof via `fin_transfer` → observe `FinTransferEvent`.
6. Assert malicious receiver's token balance equals the bridged amount — tokens received on second attempt while source-chain lock was created only once.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1670-1696)
```rust
    pub fn get_mpc_account(&self) -> AccountId {
        self.mpc_signer.clone()
    }

    pub fn get_token_decimals(&self, address: &OmniAddress) -> Option<Decimals> {
        self.token_decimals.get(address)
    }

    #[access_control_any(roles(Role::DAO, Role::TokenControllerUpdater))]
    pub fn update_tokens_controller(
        &self,
        factory_account_id: AccountId,
        tokens_accounts_id: Vec<AccountId>,
    ) {
        ext_bridge_token_facory::ext(factory_account_id)
            .with_static_gas(UPDATE_CONTROLLER_GAS)
            .set_controller_for_tokens(tokens_accounts_id)
            .detach();
    }

    #[allow(clippy::needless_pass_by_value)]
    #[private]
    pub fn fin_transfer_send_tokens_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] fee_recipient: &AccountId,
        #[serializer(borsh)] is_ft_transfer_call: bool,
```

**File:** near/omni-bridge/src/lib.rs (L1702-1718)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
```

**File:** near/omni-bridge/src/lib.rs (L1722-1732)
```rust
                if self.is_deployed_token(&token) {
                    ext_token::ext(token)
                        .with_static_gas(MINT_TOKEN_GAS)
                        .mint(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                } else {
                    ext_token::ext(token)
                        .with_attached_deposit(ONE_YOCTO)
                        .with_static_gas(FT_TRANSFER_GAS)
                        .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
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

**File:** near/omni-bridge/src/lib.rs (L2082-2117)
```rust
        } else if is_deployed_token {
            let deposit = if msg.is_empty() {
                NO_DEPOSIT
            } else {
                ONE_YOCTO
            };

            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(deposit)
                .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
                .mint(
                    recipient,
                    amount,
                    (!msg.is_empty()).then(|| msg.to_string()),
                )
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        } else {
            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(ft_transfer_call_gas)
                .ft_transfer_call(recipient, amount, None, msg.to_string())
        }
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
