### Title
Unchecked `.detach()` on Relayer Repayment in Fast-Transfer Finalization Causes Permanent Fund Loss and Escrow Mis-accounting — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

In `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast`, the bridge repays a fast-transfer relayer by calling `send_tokens(...).detach()` — a fire-and-forget cross-contract call with **no callback**. All state mutations (decrementing `locked_tokens`, marking the fast transfer as finalised) happen **before** the call and are **never reverted** if the call fails. A failed token transfer permanently destroys the relayer's pre-paid funds and leaves `locked_tokens` permanently under-counted, freezing the corresponding tokens inside the bridge contract.

The code even contains an explicit acknowledgment of the unresolved problem at the `utxo_fin_transfer_fast` call site.

---

### Finding Description

**Root cause — `process_fin_transfer_to_other_chain`**

When a cross-chain transfer whose final destination is a non-NEAR chain is finalised and a fast-transfer relayer had pre-paid the user, the bridge executes the following sequence with no error-recovery path:

```
1. add_fin_transfer(...)          // marks inbound transfer finalised (irreversible)
2. unlock_tokens_if_needed(...)   // decrements locked_tokens[origin_chain][token]
3. lock_tokens_if_needed(...)     // increments locked_tokens[dest_chain][token] (fee)
4. send_tokens(token, relayer, amount_without_fee, "").detach()   // ← NO callback
5. mark_fast_transfer_as_finalised(...)  // fast transfer entry set finalised=true
``` [1](#0-0) 

The `.detach()` call means NEAR will schedule the cross-contract call but the bridge contract **never inspects the result**. If `send_tokens` fails (e.g., `ft_transfer` panics because the relayer's account has no storage registration for the token, or the token contract is paused), all five state mutations above remain committed:

- `locked_tokens` for the origin chain is permanently decremented by `amount` even though the tokens were never transferred out.
- The fast transfer is permanently marked `finalised = true`, so it can never be retried.
- The inbound transfer is permanently in `finalised_transfers`, so it can never be re-submitted. [2](#0-1) 

**Root cause — `utxo_fin_transfer_fast`**

The identical pattern appears in the UTXO fast-transfer path. The code even carries an explicit `// TODO: check how to deal with failed send_tokens` comment at the call site, confirming the issue is known but unresolved: [3](#0-2) 

```rust
// TODO: check how to deal with failed send_tokens
return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
```

Inside `utxo_fin_transfer_fast`, `remove_fast_transfer` or `mark_fast_transfer_as_finalised` is called **before** `send_tokens(...).detach()`: [4](#0-3) 

**Contrast with the correctly handled path**

`process_fin_transfer_to_near` — the analogous function for NEAR-destined transfers — correctly chains a `fin_transfer_send_tokens_callback` that reverts lock actions and removes the finalised-transfer entry on failure: [5](#0-4) [6](#0-5) 

The other-chain path has no equivalent recovery.

**Why `send_tokens` can fail**

`send_tokens` dispatches `ft_transfer` for non-deployed (native) tokens. `ft_transfer` panics if the recipient account has no storage registration for that token: [7](#0-6) 

A relayer account that has not pre-registered storage for the specific bridged token will trigger this failure. For deployed tokens, `mint` is used instead; a paused or otherwise broken token contract produces the same silent failure.

---

### Impact Explanation

**Permanent loss of relayer funds.** The relayer pre-paid `amount_without_fee` tokens to the user on the destination chain. When the original transfer is finalised, the bridge is supposed to repay the relayer from the locked escrow. If `send_tokens` fails silently, the relayer never receives repayment. The tokens remain physically inside the bridge contract but are now unaccounted for: `locked_tokens` has been decremented as if the transfer succeeded, so the bridge believes it holds fewer tokens than it actually does.

**Permanent escrow mis-accounting / token freeze.** Because `locked_tokens[(origin_chain, token)]` is decremented without a corresponding actual outflow, the counter is permanently under-counted. Any future `unlock_tokens` call that tries to unlock the full legitimate amount will hit the `InsufficientLockedTokens` guard and revert, permanently freezing the surplus tokens inside the bridge contract with no administrative recovery path. [8](#0-7) 

---

### Likelihood Explanation

The failure condition — `ft_transfer` panicking due to missing storage registration — is a standard, well-known NEAR failure mode. A relayer that has not explicitly called `storage_deposit` on the specific token contract before being registered as a relayer will trigger it. The UTXO path carries a developer `// TODO` comment acknowledging the unresolved failure case, indicating the team is aware the scenario is reachable. The fast-transfer feature is a live, publicly accessible code path reachable by any trusted relayer.

---

### Recommendation

Mirror the pattern used in `process_fin_transfer_to_near`: replace `.detach()` with a `.then(callback)` that, on failure, re-credits the relayer's storage balance, re-increments `locked_tokens`, and un-marks the fast transfer as finalised (or re-inserts it). Alternatively, perform all state mutations only inside the success branch of the callback, keeping the pre-call state intact until the cross-contract call result is confirmed.

---

### Proof of Concept

1. Trusted relayer `R` calls `ft_transfer_call` on a non-deployed (native) token with a `FastFinTransferMsg` targeting a non-NEAR destination. `R` has not called `storage_deposit` on the token contract for its own account.
2. `fast_fin_transfer_to_other_chain` runs: `add_fast_transfer`, `burn_tokens_if_needed`, `lock_tokens_if_needed`, `add_transfer_message` all commit to state.
3. A separate relayer submits the proof via `fin_transfer` → `fin_transfer_callback` → `process_fin_transfer_to_other_chain`.
4. `unlock_tokens_if_needed` decrements `locked_tokens[(origin_chain, token)]` by `amount`. `mark_fast_transfer_as_finalised` sets `finalised = true`. `send_tokens(token, R, amount_without_fee, "").detach()` fires `ft_transfer` to `R`.
5. `ft_transfer` panics: `R` has no storage registration. The panic is silently swallowed because `.detach()` discards the result.
6. `R` never receives tokens. `locked_tokens` is permanently under-counted by `amount_without_fee`. The fast transfer entry is permanently `finalised = true`. The inbound transfer is permanently in `finalised_transfers`. No recovery is possible. [9](#0-8) [10](#0-9)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1700-1718)
```rust
        let token = self.get_token_id(&transfer_message.token);

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

**File:** near/omni-bridge/src/lib.rs (L1957-1977)
```rust
        self.send_tokens(
            token.clone(),
            recipient,
            U128(
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            ),
            &msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(SEND_TOKENS_CALLBACK_GAS)
                .fin_transfer_send_tokens_callback(
                    transfer_message,
                    &fee_recipient,
                    !msg.is_empty(),
                    predecessor_account_id,
                    lock_actions,
                ),
        )
```

**File:** near/omni-bridge/src/lib.rs (L1997-2040)
```rust
        self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        );
        self.lock_tokens_if_needed(
            transfer_message.get_destination_chain(),
            &token,
            transfer_message.fee.fee.into(),
        );

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
```

**File:** near/omni-bridge/src/lib.rs (L2102-2107)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        } else {
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

**File:** near/omni-bridge/src/lib.rs (L2270-2277)
```rust
    fn mark_fast_transfer_as_finalised(&mut self, fast_transfer_id: &FastTransferId) {
        let mut status = self
            .get_fast_transfer_status(fast_transfer_id)
            .near_expect(BridgeError::FastTransferNotFound);
        status.finalised = true;
        self.fast_transfers
            .insert(fast_transfer_id, &FastTransferStatusStorage::V0(status));
    }
```

**File:** near/omni-bridge/src/lib.rs (L2483-2548)
```rust
        if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            // TODO: check how to deal with failed send_tokens
            return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
        }

        let required_storage_balance =
            self.add_fin_utxo_transfer(&utxo_fin_transfer_msg.get_transfer_id(origin_chain));

        self.update_storage_balance(
            signer_id.clone(),
            required_storage_balance,
            NearToken::from_yoctonear(0),
        );

        if let OmniAddress::Near(recipient) = utxo_fin_transfer_msg.recipient.clone() {
            Self::utxo_fin_transfer_to_near(
                recipient,
                token_id,
                amount,
                utxo_fin_transfer_msg,
                origin_chain,
                signer_id,
            )
            .into()
        } else {
            self.utxo_fin_transfer_to_other_chain(
                token_id,
                amount,
                utxo_fin_transfer_msg,
                origin_chain,
                signer_id,
            )
        }
    }

    fn utxo_fin_transfer_fast(
        &mut self,
        fast_transfer: FastTransfer,
        fast_transfer_status: FastTransferStatus,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            !fast_transfer_status.finalised,
            BridgeError::FastTransferAlreadyFinalised.as_ref()
        );

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

**File:** near/omni-bridge/src/token_lock.rs (L71-94)
```rust
    fn unlock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(available) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        require!(
            available >= amount,
            TokenLockError::InsufficientLockedTokens.as_ref()
        );

        let remaining = available - amount;
        self.locked_tokens.insert(&key, &remaining);

        LockAction::Unlocked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
    }
```
