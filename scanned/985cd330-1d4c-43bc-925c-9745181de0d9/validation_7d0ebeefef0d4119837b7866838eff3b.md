### Title
Unchecked `send_tokens` Return Value in Fast-Transfer Finalization Causes Permanent Loss of Relayer Funds — (File: `near/omni-bridge/src/lib.rs`)

### Summary
In two fast-transfer settlement paths — `utxo_fin_transfer_fast` and `process_fin_transfer_to_other_chain` — the bridge calls `send_tokens()` with `.detach()` after irrevocably updating fast-transfer state. Because no callback is registered, a failed token transfer silently discards the relayer's reimbursement with no recovery path. The developers themselves flagged this with a `// TODO: check how to deal with failed send_tokens` comment.

### Finding Description

**Path 1 — `utxo_fin_transfer_fast` (lines 2518–2561)**

When the UTXO connector finalizes a transfer that a relayer already pre-funded via a fast transfer, the bridge:

1. Irrevocably updates fast-transfer state — either `remove_fast_transfer` (line 2530) for NEAR-destination transfers, or `mark_fast_transfer_as_finalised` (line 2533) for other-chain destinations.
2. Calls `send_tokens(...).detach()` (lines 2542–2548) to reimburse the relayer — with **no callback** and **no result check**. [1](#0-0) 

If `send_tokens` fails (e.g., `ft_transfer` panics because the relayer's account lacks storage registration for the token), the fast-transfer record is already gone and the relayer's pre-funded tokens are permanently lost. The code's own comment at the call site acknowledges the problem: [2](#0-1) 

**Path 2 — `process_fin_transfer_to_other_chain` (lines 2027–2040)**

When a cross-chain `fin_transfer` arrives and a matching fast transfer exists, the bridge:

1. Calls `send_tokens(...).detach()` (lines 2029–2039) to reimburse the relayer — again with **no callback**.
2. Immediately calls `mark_fast_transfer_as_finalised` (line 2040). [3](#0-2) 

If `send_tokens` fails, the fast transfer is still marked finalised and the relayer's reimbursement is silently dropped.

**Contrast with the correct pattern elsewhere**

Every other `send_tokens` call in the bridge registers a callback that checks the result and reverts state on failure:

- `fast_fin_transfer_to_near_callback` → `.then(resolve_fast_transfer(...))` [4](#0-3) 
- `process_fin_transfer_to_near` → `.then(fin_transfer_send_tokens_callback(...))` [5](#0-4) 
- `utxo_fin_transfer_to_near_callback` → `.then(resolve_utxo_fin_transfer(...))` [6](#0-5) 

The `is_refund_required` helper and `revert_lock_actions` exist precisely to undo state when a transfer fails: [7](#0-6) 

The two detached paths skip this entire safety net.

### Impact Explanation
A relayer who pre-funded a fast transfer permanently loses their bridged tokens if the reimbursement `send_tokens` call fails. The fast-transfer record is already deleted or finalised before the call, so there is no retry path and no on-chain state left to trigger recovery. This is a direct, permanent loss of bridged funds held by a legitimate bridge participant.

### Likelihood Explanation
The failure condition is realistic: `ft_transfer` panics if the recipient (the relayer) has not registered storage for the token contract. A relayer operating across many tokens may not have pre-registered storage for every token. Additionally, gas exhaustion in the detached promise can silently drop the transfer. No attacker action is required — the bug is triggered by normal bridge operation.

### Recommendation
Replace `.detach()` with a `.then(callback)` that checks the promise result and, on failure, re-inserts the fast-transfer record (or re-credits the relayer's storage balance) so the reimbursement can be retried. This mirrors the pattern already used in `resolve_fast_transfer` and `fin_transfer_send_tokens_callback`.

### Proof of Concept

1. Trusted relayer executes a fast transfer for a BTC→NEAR transfer: sends tokens to the NEAR recipient ahead of the UTXO confirmation.
2. UTXO connector calls `verify_deposit`, which triggers `ft_transfer_call` → `ft_on_transfer` → `utxo_fin_transfer` on the bridge.
3. A matching fast-transfer status is found; `utxo_fin_transfer_fast` is entered.
4. `remove_fast_transfer` is called — the fast-transfer record is deleted from storage. [8](#0-7) 
5. `send_tokens(fast_transfer.token_id, relayer, amount, "").detach()` is called. [9](#0-8) 
6. The relayer's account has no storage registered for the token → `ft_transfer` panics inside the detached promise.
7. The bridge's `ft_on_transfer` returns `U128(0)` (success from the bridge's perspective), the UTXO transfer is marked complete, and the relayer's pre-funded tokens are permanently lost with no on-chain record remaining.

### Citations

**File:** near/omni-bridge/src/lib.rs (L877-892)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L994-1011)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L2027-2041)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L2483-2486)
```rust
        if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            // TODO: check how to deal with failed send_tokens
            return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
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
