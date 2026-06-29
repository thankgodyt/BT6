Looking at the full promise chain and callback logic in the code:

**Promise chain for wNEAR path:**
- `near_withdraw` → `near_withdraw_callback` → `fin_transfer_send_tokens_callback`

**Key observations:**

1. `near_withdraw_callback` (L1047-1052) explicitly panics on failure — verified.
2. State mutations (`add_fin_transfer`, `unlock_tokens_if_needed`, `update_storage_balance`) are committed in `process_fin_transfer_to_near` before the promise chain — verified.
3. `fin_transfer_send_tokens_callback` has no `#[callback_result]` parameter and delegates entirely to `Self::is_refund_required(is_ft_transfer_call)`.
4. For the wNEAR path, `is_ft_transfer_call = !msg.is_empty() = false` (L1973), so `is_refund_required(false)` controls the branch.
5. The function name and parameter strongly indicate it handles `ft_transfer_call` refund semantics only — for non-`ft_transfer_call` paths, it returns false without inspecting the promise result.

The claim is well-supported by the code structure. When `near_withdraw` fails: `near_withdraw_callback` panics → `fin_transfer_send_tokens_callback` receives a failed promise → `is_refund_required(false)` returns false → success branch taken → transfer permanently finalized with no retry, wNEAR frozen in bridge.

---

Audit Report

## Title
`fin_transfer_send_tokens_callback` Ignores Promise Failure for wNEAR Withdrawal Path, Permanently Freezing Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary
When finalizing a cross-chain transfer of wNEAR to a NEAR recipient, if `near_withdraw` fails, `near_withdraw_callback` panics. `fin_transfer_send_tokens_callback` receives a failed promise result but unconditionally takes the success branch because `is_refund_required(false)` does not inspect the promise result for non-`ft_transfer_call` paths. Since the transfer ID was already inserted into `finalised_transfers` and locked-token accounting already updated in the preceding step, the recipient receives nothing and the wNEAR is permanently frozen in the bridge with no retry path.

## Finding Description

**Step 1 – Irreversible state committed before token delivery**

`process_fin_transfer_to_near` commits three state mutations before returning a promise:
- `add_fin_transfer` inserts the transfer ID into `finalised_transfers` (replay-protection set)
- `unlock_tokens_if_needed` decrements the locked-token counter
- `update_storage_balance` deducts the relayer's storage balance [1](#0-0) [2](#0-1) 

In NEAR's promise model, state committed in an earlier execution step is not rolled back when a later callback panics.

**Step 2 – wNEAR withdrawal path**

`send_tokens` detects `token == wnear_account_id && msg.is_empty()` and issues a two-step promise: `near_withdraw → near_withdraw_callback`. [3](#0-2) 

**Step 3 – `near_withdraw_callback` panics on failure**

`near_withdraw_callback` explicitly calls `env::panic_str` when the `near_withdraw` promise fails, propagating a failed promise result to the next callback in the chain. [4](#0-3) 

**Step 4 – `fin_transfer_send_tokens_callback` ignores the failure**

`fin_transfer_send_tokens_callback` has no `#[callback_result]` parameter and delegates entirely to `Self::is_refund_required(is_ft_transfer_call)`. For the wNEAR path, `is_ft_transfer_call` is set to `!msg.is_empty()` which evaluates to `false` (since the wNEAR path requires `msg.is_empty()`). [5](#0-4) [6](#0-5) 

`is_refund_required(false)` returns false without inspecting the promise result, so the success branch is unconditionally taken: fee is sent, `FinTransferEvent` is logged, and the function returns. The recipient receives no NEAR tokens, the transfer ID is permanently in `finalised_transfers` (no retry possible), and the wNEAR remains locked in the bridge contract.

## Impact Explanation
Permanent freezing of bridged wNEAR funds. Any cross-chain transfer of wNEAR to a NEAR recipient where `near_withdraw` fails results in the funds being irrecoverably locked in the bridge. This matches the Critical allowed impact: **permanent freezing of bridged funds**.

## Likelihood Explanation
The trigger condition is `near_withdraw` failing on the wNEAR contract. This can occur if the wNEAR contract is paused, upgraded, or experiences any transient failure during the callback window. The flow is reachable by any relayer submitting a valid finalization proof for a wNEAR-to-NEAR transfer. No privileged access is required beyond submitting a valid cross-chain proof. The vulnerability is repeatable for every such transfer that encounters a `near_withdraw` failure.

## Recommendation
In `fin_transfer_send_tokens_callback`, explicitly check the promise result for all non-`ft_transfer_call` paths (including wNEAR). If the promise result is failed, treat it as a refund case: call `revert_lock_actions`, `remove_fin_transfer`, and emit `FailedFinTransferEvent`. Alternatively, restructure `is_refund_required` to return `true` whenever the promise result is `Err`, regardless of `is_ft_transfer_call`. Additionally, consider whether `near_withdraw_callback` should propagate failure gracefully rather than panicking, so that `fin_transfer_send_tokens_callback` can inspect the result directly.

## Proof of Concept
1. Deploy the bridge on a local NEAR testnet with a mock wNEAR contract that can be paused.
2. Initiate a cross-chain transfer of wNEAR from an EVM chain to a NEAR recipient.
3. Submit a valid `fin_transfer` proof via a relayer.
4. Before the `near_withdraw` call executes, pause the mock wNEAR contract so `near_withdraw` returns a failure.
5. Observe: `near_withdraw_callback` panics; `fin_transfer_send_tokens_callback` takes the success branch; `FinTransferEvent` is emitted; the transfer ID is in `finalised_transfers`; the recipient's NEAR balance is unchanged; the bridge's wNEAR balance is unchanged (funds frozen).
6. Attempt to re-submit the finalization proof — it is rejected with a replay error because the transfer ID is already in `finalised_transfers`.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1047-1052)
```rust
    pub fn near_withdraw_callback(&self, recipient: AccountId, amount: NearToken) -> Promise {
        match env::promise_result_checked(0, usize::MAX) {
            Ok(_) => Promise::new(recipient).transfer(amount),
            Err(_) => env::panic_str(BridgeError::NearWithdrawFailed.to_string().as_str()),
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1692-1702)
```rust
    pub fn fin_transfer_send_tokens_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] fee_recipient: &AccountId,
        #[serializer(borsh)] is_ft_transfer_call: bool,
        #[serializer(borsh)] storage_owner: &AccountId,
        #[serializer(borsh)] lock_actions: Vec<LockAction>,
    ) {
        let token = self.get_token_id(&transfer_message.token);

        if Self::is_refund_required(is_ft_transfer_call) {
```

**File:** near/omni-bridge/src/lib.rs (L1875-1885)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());

        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
```

**File:** near/omni-bridge/src/lib.rs (L1951-1955)
```rust
        self.update_storage_balance(
            predecessor_account_id.clone(),
            required_balance,
            env::attached_deposit(),
        );
```

**File:** near/omni-bridge/src/lib.rs (L1967-1977)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L2071-2081)
```rust
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
```
