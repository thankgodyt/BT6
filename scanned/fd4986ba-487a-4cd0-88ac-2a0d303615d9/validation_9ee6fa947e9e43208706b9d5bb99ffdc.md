### Title
Fire-and-Forget Relayer Repayment in Fast-Transfer Finalization Permanently Loses Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

### Summary

In `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast`, the bridge repays a fast-transfer relayer by calling `send_tokens(...).detach()` — a fire-and-forget promise with no failure callback. The fast transfer is immediately marked as finalised before the token transfer result is known. If the token transfer fails (e.g., the relayer's account lacks NEP-141 storage registration for the token), the relayer's pre-funded bridged tokens are permanently lost with no retry path.

### Finding Description

When a cross-chain transfer is finalized via `fin_transfer` → `fin_transfer_callback` → `process_fin_transfer_to_other_chain`, the bridge checks whether a fast-transfer relayer pre-funded the user's transfer. If so, it must repay the relayer:

```rust
// near/omni-bridge/src/lib.rs lines 2028-2040
if let Some(relayer) = recipient {
    self.send_tokens(
        token,
        relayer,
        U128(transfer_message.amount_without_fee()...),
        "",
    )
    .detach();                                              // ← fire-and-forget
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // ← already done
}
``` [1](#0-0) 

The `.detach()` call discards the promise result entirely. `mark_fast_transfer_as_finalised` is called unconditionally immediately after, so the fast-transfer record is permanently closed regardless of whether the token transfer succeeded or failed.

The same pattern appears in `utxo_fin_transfer_fast`, where the fast transfer is removed or finalised **before** the detached `send_tokens` call:

```rust
// near/omni-bridge/src/lib.rs lines 2529-2548
let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
    self.remove_fast_transfer(&fast_transfer.id());   // ← already removed
    fast_transfer.amount
} else {
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // ← already finalised
    ...
};
self.send_tokens(...fast_transfer_status.relayer...).detach(); // ← fire-and-forget
``` [2](#0-1) 

`send_tokens` for a non-deployed token with an empty `msg` calls `ft_transfer`:

```rust
// near/omni-bridge/src/lib.rs lines 2102-2106
} else if msg.is_empty() {
    ext_token::ext(token)
        .with_attached_deposit(ONE_YOCTO)
        .with_static_gas(FT_TRANSFER_GAS)
        .ft_transfer(recipient, amount, None)
}
``` [3](#0-2) 

NEP-141 `ft_transfer` panics if the recipient account has not registered storage for that token. Since the promise is detached, this panic is silently swallowed. The fast transfer is already finalised, so there is no mechanism to retry or recover the funds.

A secondary instance of the same pattern exists in `fin_transfer_send_tokens_callback` where fee payments to the fee recipient are also fire-and-forget:

```rust
ext_token::ext(token)
    .with_attached_deposit(ONE_YOCTO)
    .with_static_gas(FT_TRANSFER_GAS)
    .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
    .detach();
``` [4](#0-3) 

### Impact Explanation

A fast-transfer relayer pre-funds the user's transfer out of their own balance. When the on-chain proof is finalized, the bridge is supposed to repay the relayer the full `amount_without_fee`. If the `ft_transfer` to the relayer fails and the promise is detached, the relayer's tokens are permanently locked inside the bridge contract with no recovery path. The fast transfer is already marked finalised, so `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast` cannot be re-entered for the same transfer ID. This constitutes permanent loss of bridged funds.

### Likelihood Explanation

The failure condition is realistic and attacker-controllable: a malicious user can set the `fee_recipient` or arrange for the relayer account to lack storage registration for the specific token being transferred. Additionally, any transient failure in the token contract (e.g., a panic in a custom NEP-141 implementation) silently causes permanent loss. The entry path is fully unprivileged — any user can submit a cross-chain proof via `fin_transfer`, and any trusted relayer can execute a fast transfer.

### Recommendation

Replace the `.detach()` pattern with a chained callback that checks the result of `send_tokens`. If the token transfer fails, the fast transfer should be un-finalised (or the relayer's claim should be stored for retry), and the tokens should remain recoverable. Specifically:

1. In `process_fin_transfer_to_other_chain`, call `mark_fast_transfer_as_finalised` only inside a success callback of `send_tokens`, not unconditionally before it.
2. In `utxo_fin_transfer_fast`, do not remove/finalise the fast transfer record until the `send_tokens` promise resolves successfully.
3. In `fin_transfer_send_tokens_callback`, add a callback to the fee `ft_transfer` that can store unclaimed fees for later retry if the transfer fails.

### Proof of Concept

1. Trusted relayer calls `ft_transfer_call` with `FastFinTransferMsg` to pre-fund a user's cross-chain transfer. The fast transfer record is stored in `fast_transfers`.
2. The user's proof is submitted via `fin_transfer` → `fin_transfer_callback` → `process_fin_transfer_to_other_chain`.
3. The bridge detects the existing fast transfer and calls `send_tokens(token, relayer, amount, "").detach()`.
4. The relayer's NEAR account has not registered storage for `token` (e.g., a newly bridged ERC-20). The `ft_transfer` panics inside the token contract.
5. Because the promise is detached, the panic is silently ignored. `mark_fast_transfer_as_finalised` has already been called.
6. The relayer's `amount_without_fee` tokens remain locked in the bridge contract. The fast transfer ID is finalised and cannot be re-submitted. The relayer has no recourse. [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1728-1733)
```rust
                    ext_token::ext(token)
                        .with_attached_deposit(ONE_YOCTO)
                        .with_static_gas(FT_TRANSFER_GAS)
                        .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                }
```

**File:** near/omni-bridge/src/lib.rs (L2008-2041)
```rust
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let recipient = if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            require!(
                !status.finalised,
                BridgeError::FastTransferAlreadyFinalised.as_ref()
            );
            Some(status.relayer)
        } else {
            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token,
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            );

            None
        };

        // If fast transfer happened, send tokens to the relayer that executed fast transfer
        if let Some(relayer) = recipient {
            self.send_tokens(
                token,
                relayer,
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
                "",
            )
            .detach();
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
        } else {
```

**File:** near/omni-bridge/src/lib.rs (L2056-2117)
```rust
    fn send_tokens(
        &self,
        token: AccountId,
        recipient: AccountId,
        amount: U128,
        msg: &str,
    ) -> Promise {
        let ft_transfer_call_gas = env::prepaid_gas()
            .saturating_sub(env::used_gas())
            .saturating_sub(SEND_TOKENS_CALLBACK_GAS) // TODO: not all send_tokens callbacks has the same gas.
            .saturating_sub(MINT_TOKEN_GAS)
            .min(FT_TRANSFER_CALL_GAS);

        let is_deployed_token = self.is_deployed_token(&token);

        if token == self.wnear_account_id && msg.is_empty() {
            // Unwrap wNEAR and transfer NEAR tokens
            ext_wnear_token::ext(self.wnear_account_id.clone())
                .with_static_gas(WNEAR_WITHDRAW_GAS)
                .with_attached_deposit(ONE_YOCTO)
                .near_withdraw(amount)
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(NEAR_WITHDRAW_CALLBACK_GAS)
                        .near_withdraw_callback(recipient, NearToken::from_yoctonear(amount.0)),
                )
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

**File:** near/omni-bridge/src/lib.rs (L2529-2548)
```rust
        let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
            self.remove_fast_transfer(&fast_transfer.id());
            fast_transfer.amount
        } else {
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
            // With transfers to other chain the fee will be claimed after finalization on the destination chain
            U128(
                fast_transfer
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            )
        };

        self.send_tokens(
            fast_transfer.token_id.clone(),
            fast_transfer_status.relayer,
            amount,
            "",
        )
        .detach();
```
