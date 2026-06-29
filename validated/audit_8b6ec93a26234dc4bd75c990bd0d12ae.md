### Title
`finalised_transfers` Marked Before Token Delivery; Failed `ft_transfer_call` Panic Permanently Freezes User Funds - (`File: near/omni-bridge/src/lib.rs`)

### Summary

In `process_fin_transfer_to_near`, the transfer is inserted into `finalised_transfers` (replay-protection set) **before** the asynchronous token delivery executes. The cleanup callback `fin_transfer_send_tokens_callback` only removes the finalization record when `is_refund_required` returns `true`. However, `is_refund_required` returns `false` when the `ft_transfer_call` promise result is an error (`Err(_)`), meaning a panic in the recipient's `ft_on_transfer` leaves the finalization record permanently set while the tokens are never delivered. The proof cannot be resubmitted (blocked by `TransferAlreadyFinalised`), and there is no recovery path.

### Finding Description

`process_fin_transfer_to_near` executes in two NEAR transactions:

**Transaction 1 – `fin_transfer_callback`:** [1](#0-0) 

`add_fin_transfer` inserts the `TransferId` into `finalised_transfers` and this state change is committed when the callback returns. The function then dispatches `send_tokens` and chains `fin_transfer_send_tokens_callback`. [2](#0-1) 

**Transaction 2 – `fin_transfer_send_tokens_callback`:**

The callback decides whether to clean up via `is_refund_required`: [3](#0-2) 

`is_refund_required` is: [4](#0-3) 

The critical branch is `Err(_) => false` at line 1798. When `ft_transfer_call` panics (e.g., the recipient contract's `ft_on_transfer` panics), `promise_result_checked` returns `Err`, `is_refund_required` returns `false`, and `remove_fin_transfer` is **never called**. The finalization record persists, but the tokens were never delivered (the failed `ft_transfer_call` reverts the token movement back to the bridge).

`add_fin_transfer` enforces uniqueness: [5](#0-4) 

Any attempt to resubmit the same proof panics with `TransferAlreadyFinalised`. There is no admin or user-callable function to remove an entry from `finalised_transfers` outside of the callback path.

The same issue applies to the plain `ft_transfer` (no-`msg`) path: `is_ft_transfer_call` is `false` (line 1973 passes `!msg.is_empty()`), so `is_refund_required` unconditionally returns `false` regardless of whether the underlying `ft_transfer` cross-contract call succeeded or failed. [6](#0-5) 

### Impact Explanation

Bridged funds are permanently frozen inside the NEAR `omni-bridge` contract. The user's tokens on the origin chain (EVM/Solana/etc.) were already locked or burned when the `InitTransfer` event was emitted. On the NEAR side, the finalization record blocks any re-proof, and no recovery function exists. This constitutes **permanent loss of bridged funds**.

### Likelihood Explanation

Any transfer that includes a non-empty `msg` (directing tokens to a recipient contract via `ft_transfer_call`) is at risk. The recipient contract's `ft_on_transfer` can panic due to:
- The target DeFi protocol being paused
- A bug in the recipient contract
- Insufficient gas forwarded to the recipient

This is a realistic, user-reachable scenario requiring no privileged access. The user only needs to submit a valid cross-chain transfer with a `msg` field targeting any contract that can panic.

### Recommendation

1. **Treat `Err(_)` as a refund condition.** In `is_refund_required`, change the `Err(_) => false` branch to `Err(_) => true` so that a panicking `ft_transfer_call` triggers cleanup.

2. **Handle plain `ft_transfer` failures.** When `is_ft_transfer_call` is `false`, check the promise result of the `ft_transfer` call and remove the finalization record if it failed.

3. **Remove finalization record on any delivery failure.** `remove_fin_transfer` should be called whenever token delivery does not succeed, mirroring the pattern already used for the `ft_transfer_call` refund case at line 1714.

### Proof of Concept

1. User initiates a transfer from Ethereum to NEAR with a non-empty `msg` targeting a recipient contract `R`.
2. Relayer submits proof; `fin_transfer_callback` runs, `add_fin_transfer` commits the `TransferId` to `finalised_transfers`, and `ft_transfer_call` is dispatched to token contract → `R`.
3. `R.ft_on_transfer` panics (e.g., protocol is paused).
4. `fin_transfer_send_tokens_callback` is called; `promise_result_checked(0, …)` returns `Err(_)`; `is_refund_required` returns `false`; no cleanup.
5. `finalised_transfers` still contains the `TransferId`. Tokens were reverted to the bridge contract.
6. Relayer attempts to resubmit the proof → panics with `ERR_TRANSFER_ALREADY_FINALISED`.
7. User's funds are permanently frozen with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1702-1714)
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
```

**File:** near/omni-bridge/src/lib.rs (L1784-1803)
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
```

**File:** near/omni-bridge/src/lib.rs (L1875-1875)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
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
