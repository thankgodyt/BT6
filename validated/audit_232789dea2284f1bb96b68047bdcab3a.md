### Title
Partial `ft_on_transfer` Refund Causes Bridged Tokens to Be Permanently Stuck in Bridge Contract - (`near/omni-bridge/src/lib.rs`)

### Summary

When the NEAR bridge finalizes an inbound transfer with a non-empty `msg` field (triggering `ft_transfer_call`), the bridge's refund logic only handles two cases: full rejection (`amount == 0`) and full acceptance (`amount > 0`). If the recipient's `ft_on_transfer` returns a non-zero partial amount (i.e., it used only some of the tokens), the partially refunded tokens are silently retained in the bridge contract with no recovery path, while the transfer is simultaneously marked as finalized.

### Finding Description

The bridge's `is_refund_required` function determines whether to revert a finalized transfer based on the result of `ft_transfer_call`: [1](#0-0) 

The function returns `true` (revert the transfer) only when `amount.0 == 0`, meaning the recipient used zero tokens. If the recipient returns any non-zero amount — even if it is less than the full transfer amount — `is_refund_required` returns `false`, and the bridge proceeds to emit `FinTransferEvent` as if the transfer fully succeeded. [2](#0-1) 

Meanwhile, the NEP-141 token contract's `ft_resolve_transfer` has already refunded the partial amount back to the bridge contract's token balance. The bridge has no code path to forward these returned tokens to the original recipient or the sender. They are permanently stranded.

The same flaw exists in `resolve_fast_transfer`: [3](#0-2) 

And in `resolve_utxo_fin_transfer`: [4](#0-3) 

The integration test suite explicitly demonstrates this behavior. For a non-deployed token transfer of 1000 with fee=1, when the recipient returns 1 token (partial refund), the bridge retains 1 token permanently: [5](#0-4) 

The `expected_locker_balance: 1` confirms the token is stuck in the bridge. The transfer is finalized (the foreign-chain sender's tokens are already burned/locked), so there is no retry path.

### Impact Explanation

For non-deployed tokens (e.g., USDC, WETH locked in the bridge): the partially refunded tokens accumulate in the bridge contract's token balance with no withdrawal or recovery function. The foreign-chain sender has already irrevocably burned or locked their tokens. The NEAR recipient receives fewer tokens than expected. The residual amount is permanently frozen.

For deployed (bridge-minted) tokens: the returned tokens are burned by the token contract's `ft_resolve_transfer`, destroying supply that was legitimately owed to the user.

In both cases, the user suffers a direct, unrecoverable loss of bridged funds.

### Likelihood Explanation

The attack surface is any `fin_transfer` or `fast_fin_transfer` call that includes a non-empty `msg` field. This is a supported and documented feature for DeFi integrations (e.g., swapping received tokens on a DEX). Any recipient contract that:
- Enforces a minimum output (slippage protection),
- Has insufficient liquidity for the full amount,
- Implements any partial-fill logic,

will return a non-zero amount from `ft_on_transfer`. This is standard NEP-141 behavior and is not an edge case. The `msg` field is user-controlled and relayer-submitted, making this reachable by any bridge user.

### Recommendation

In `fin_transfer_send_tokens_callback`, `resolve_fast_transfer`, and `resolve_utxo_fin_transfer`, after determining that `is_refund_required` is false, check whether the actual used amount equals the expected amount. If a partial refund occurred (used amount < sent amount), forward the residual tokens to the original recipient or the transfer sender rather than leaving them in the bridge.

Concretely, `is_refund_required` should be replaced with a function that returns the actual used amount, and any shortfall should be forwarded:

```rust
// Instead of binary is_refund_required, read the actual used amount
let used_amount = get_used_amount_from_promise();
let residual = sent_amount - used_amount;
if residual > 0 {
    // forward residual to recipient or original sender
}
```

### Proof of Concept

1. User on Ethereum initiates a transfer of 1000 USDC to NEAR with `msg = "<dex_swap_params>"`.
2. Relayer submits proof to `fin_transfer` on NEAR.
3. Bridge calls `ft_transfer_call(recipient_dex, 999, msg)` (999 = amount minus fee).
4. Recipient DEX's `ft_on_transfer` can only fill 500 USDC worth of the swap; it returns `U128(499)`.
5. Token contract's `ft_resolve_transfer` refunds 499 USDC to the bridge contract.
6. `fin_transfer_send_tokens_callback` is called; `is_refund_required` sees `amount.0 = 500 != 0`, returns `false`.
7. Bridge emits `FinTransferEvent` — transfer is finalized.
8. 499 USDC sit in the bridge contract's balance permanently. The user's Ethereum USDC is already burned. Net loss: 499 USDC. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L895-912)
```rust
    #[private]
    pub fn resolve_fast_transfer(
        &mut self,
        token_id: &AccountId,
        fast_transfer_id: &FastTransferId,
        amount: U128,
        is_ft_transfer_call: bool,
    ) -> U128 {
        // Burn the tokens to ensure the locked tokens are not double-minted
        self.burn_tokens_if_needed(token_id.clone(), amount);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
        }
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

**File:** near/omni-tests/src/fin_transfer.rs (L533-545)
```rust
    #[case(FinTransferWithMsgCase {
        storage_deposit_accounts: vec![(relayer_account_id(), true)],
        amount: 1000,
        fee: 1,
        msg: TokenReceiverMessage {
            return_value: U128(1),
            panic: false,
            extra_msg: String::new(),
        },
        expected_recipient_balance: 998,
        expected_relayer_balance: 1,
        expected_locker_balance: 1,
    })]
```
