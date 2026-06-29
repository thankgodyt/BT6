### Title
`locked_tokens` Mis-Accounting Due to Fire-and-Forget `send_tokens` in Fast-Transfer Finalization — (File: `near/omni-bridge/src/lib.rs`)

### Summary

In `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast`, the bridge updates its internal `locked_tokens` accounting and marks the fast transfer as finalised **before** the actual token disbursement to the relayer, which is dispatched with `.detach()`. If the token transfer fails, the accounting is permanently corrupted and the relayer's pre-paid funds are irrecoverably lost.

### Finding Description

When a cross-chain transfer has been pre-paid by a fast-transfer relayer and the canonical proof arrives via `fin_transfer` → `fin_transfer_callback` → `process_fin_transfer_to_other_chain`, the function executes the following sequence:

1. `unlock_tokens_if_needed(origin_chain, token, amount)` — decrements `locked_tokens[(origin_chain, token)]`
2. `lock_tokens_if_needed(destination_chain, token, fee)` — increments `locked_tokens[(destination_chain, token)]`
3. `send_tokens(token, relayer, amount_without_fee, "").detach()` — fires the actual token transfer to the relayer and **discards the result**
4. `mark_fast_transfer_as_finalised(fast_transfer_id)` — permanently closes the fast-transfer record [1](#0-0) 

Because `.detach()` drops the promise result, any failure of `send_tokens` (token contract paused, insufficient gas forwarded, token contract panic) is silently swallowed. Steps 1, 2, and 4 are **not reverted**. The same pattern exists in `utxo_fin_transfer_fast`, where the codebase itself contains an explicit `// TODO: check how to deal with failed send_tokens` comment acknowledging the gap: [2](#0-1) [3](#0-2) 

Contrast this with the NEAR-recipient path (`process_fin_transfer_to_near`), which correctly chains `send_tokens` with a `fin_transfer_send_tokens_callback` that reverts `lock_actions` on failure: [4](#0-3) [5](#0-4) 

The `locked_tokens` map is the bridge's sole on-chain invariant linking its token custody to cross-chain obligations: [6](#0-5) [7](#0-6) 

### Impact Explanation

**Relayer fund loss.** The fast-transfer relayer pre-paid the recipient out of their own balance. When `fin_transfer` is called to reimburse them, `send_tokens` may fail silently. The fast transfer is marked finalised (no retry path), so the relayer's tokens are permanently lost.

**Permanent `locked_tokens` corruption.** `locked_tokens[(origin_chain, token)]` is decremented without the corresponding token leaving the bridge. The bridge now holds more tokens than `locked_tokens` accounts for. Subsequent `unlock_tokens` calls for the same `(origin_chain, token)` pair will eventually hit `ERR_INSUFFICIENT_LOCKED_TOKENS` even though the bridge physically holds the tokens, blocking all future legitimate `fin_transfer` completions for that token/chain pair. For deployed (mintable) tokens the mirror effect applies: `locked_tokens[(destination_chain, token)]` is incremented for the fee without the fee being minted, inflating the accounting on the destination side.

### Likelihood Explanation

The trigger requires a fast transfer to be in flight when `fin_transfer` is called, and `send_tokens` to fail. Realistic failure modes:

- The token contract (e.g., USDC, USDT) is **paused by its issuer** between the fast-transfer execution and the canonical `fin_transfer` call — a well-documented operational event for regulated stablecoins.
- The token contract panics due to a bug or upgrade.
- Insufficient gas is forwarded to the detached promise (the gas budget calculation at lines 2063–2067 uses `saturating_sub`, which can produce a very small value). [8](#0-7) 

Fast transfers are a core, publicly accessible bridge feature reachable by any trusted relayer via `ft_on_transfer` → `fast_fin_transfer`.

### Recommendation

Replace the `.detach()` pattern with a chained callback that reverts the `locked_tokens` changes and un-finalises (or removes) the fast-transfer record on failure, mirroring the existing `fin_transfer_send_tokens_callback` pattern used for NEAR-recipient transfers. Specifically:

- In `process_fin_transfer_to_other_chain`, chain `send_tokens` with a callback that calls `revert_lock_actions` and `remove_fast_transfer` on failure.
- In `utxo_fin_transfer_fast`, apply the same pattern (resolving the existing TODO).
- Ensure `mark_fast_transfer_as_finalised` is only called inside the success branch of the callback, not before the promise resolves.

### Proof of Concept

1. Relayer R executes `fast_fin_transfer` for a USDC transfer from Ethereum to Solana, pre-paying the Solana recipient. `locked_tokens[(Eth, USDC)]` = 1000, fast transfer recorded.
2. USDC contract is paused by Circle.
3. Any relayer calls `fin_transfer` with the canonical Ethereum proof.
4. `fin_transfer_callback` → `process_fin_transfer_to_other_chain`:
   - `unlock_tokens_if_needed(Eth, USDC, 1000)` → `locked_tokens[(Eth, USDC)]` = 0
   - `lock_tokens_if_needed(Sol, USDC, fee)` → `locked_tokens[(Sol, USDC)]` += fee
   - `send_tokens(USDC, R, 1000 - fee, "").detach()` → **fails silently** (USDC paused)
   - `mark_fast_transfer_as_finalised(...)` → fast transfer closed permanently
5. Relayer R never receives their USDC. `locked_tokens[(Eth, USDC)]` = 0 despite the bridge still holding 1000 USDC. All future `fin_transfer` calls for USDC from Ethereum fail with `ERR_INSUFFICIENT_LOCKED_TOKENS`, permanently freezing those user funds. [9](#0-8) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L242-242)
```rust
    pub locked_tokens: LookupMap<(ChainKind, AccountId), u128>,
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

**File:** near/omni-bridge/src/lib.rs (L2063-2067)
```rust
        let ft_transfer_call_gas = env::prepaid_gas()
            .saturating_sub(env::used_gas())
            .saturating_sub(SEND_TOKENS_CALLBACK_GAS) // TODO: not all send_tokens callbacks has the same gas.
            .saturating_sub(MINT_TOKEN_GAS)
            .min(FT_TRANSFER_CALL_GAS);
```

**File:** near/omni-bridge/src/lib.rs (L2483-2486)
```rust
        if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            // TODO: check how to deal with failed send_tokens
            return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
        }
```

**File:** near/omni-bridge/src/lib.rs (L2518-2548)
```rust
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
