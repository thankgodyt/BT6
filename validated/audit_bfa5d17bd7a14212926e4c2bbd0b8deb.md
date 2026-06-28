### Title
Silent `ft_transfer` Failure Permanently Freezes Bridged Funds — (`File: near/omni-bridge/src/lib.rs`)

### Summary

`fin_transfer_send_tokens_callback` never inspects the promise result when the token delivery path is a plain `ft_transfer` (i.e., `is_ft_transfer_call = false`). If `ft_transfer` fails — for example because the NEAR recipient is on a token-contract denylist (USDC, USDT) — the callback silently treats the delivery as successful: it pays the relayer fee, emits `FinTransferEvent`, and leaves the transfer ID permanently in `finalised_transfers`. The proof is consumed and cannot be replayed, so the bridged tokens are frozen in the bridge contract forever with no recovery path.

### Finding Description

`process_fin_transfer_to_near` calls `send_tokens` and chains `fin_transfer_send_tokens_callback` as the resolution callback. The flag `is_ft_transfer_call` is set to `!msg.is_empty()` (line 1973). When `msg` is empty, `send_tokens` issues a plain `ft_transfer` (lines 2102–2106) and `is_ft_transfer_call` is `false`.

Inside `fin_transfer_send_tokens_callback`, the only gate for the failure path is:

```rust
if Self::is_refund_required(is_ft_transfer_call) { … }
```

`is_refund_required` (lines 1784–1804) reads:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) { … }
    } else {
        // Not ft_transfer_call: don't refund
        false          // ← promise result is NEVER checked
    }
}
```

When `is_ft_transfer_call = false`, the function returns `false` unconditionally, regardless of whether the underlying `ft_transfer` promise succeeded or failed. The callback therefore always falls into the `else` branch (lines 1719–1746), which:

1. Mints/transfers the fee to the relayer.
2. Emits `FinTransferEvent`.
3. Does **not** call `remove_fin_transfer`.

The transfer ID was inserted into `finalised_transfers` at line 1875 (`add_fin_transfer`) before the promise chain. Because `remove_fin_transfer` is only called in the refund branch (line 1714), the ID stays in `finalised_transfers` permanently, making replay impossible. The tokens remain locked in the bridge contract with no mechanism to recover them.

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

When `ft_transfer` fails:
- The cross-chain proof is consumed (transfer ID in `finalised_transfers`); the same proof cannot be submitted again.
- The bridged tokens (e.g., USDC) remain locked inside the bridge contract.
- The recipient receives nothing.
- The relayer is paid the fee as if the transfer succeeded.
- There is no admin escape hatch or retry mechanism in the contract.

The user's funds are permanently unrecoverable.

### Likelihood Explanation

**Medium.** Several widely-bridged ERC-20 tokens (USDC, USDT, WBTC) implement on-chain denylists. If a NEAR recipient account is on such a denylist, `ft_transfer` will panic and return a failed promise. This is a realistic, externally-triggerable condition: any user who initiates a cross-chain transfer to a blacklisted NEAR address (or whose address is blacklisted after the transfer is initiated on the source chain) will trigger this path. No privileged access is required.

### Recommendation

`is_refund_required` must also check the promise result for the plain `ft_transfer` path. The simplest fix is to inspect `env::promise_result_checked(0, …)` regardless of `is_ft_transfer_call`, and treat a failed promise as requiring a refund/burn:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
        Err(_) => true,   // ft_transfer or ft_transfer_call panicked → refund
        Ok(value) if is_ft_transfer_call => {
            near_sdk::serde_json::from_slice::<U128>(&value)
                .map_or(false, |a| a.0 == 0)
        }
        Ok(_) => false,   // ft_transfer succeeded
    }
}
```

This ensures that a failed `ft_transfer` triggers `burn_tokens_if_needed`, `revert_lock_actions`, and `remove_fin_transfer`, allowing the proof to be re-submitted after the underlying issue is resolved, or at minimum preventing silent fund loss.

### Proof of Concept

**Precondition:** USDC is a non-deployed (locked) token on the NEAR bridge. Alice's NEAR account `alice.near` is on USDC's denylist.

1. Alice initiates a transfer of 1000 USDC from Ethereum to `alice.near` via `OmniBridge.sol::initTransfer`.
2. A relayer observes the event, generates a proof, and calls `fin_transfer` on the NEAR bridge with valid `prover_args`.
3. `fin_transfer_callback` (line 700) decodes the proof, constructs `transfer_message` with `msg = ""`, and calls `process_fin_transfer_to_near`.
4. `process_fin_transfer_to_near` (line 1875) calls `add_fin_transfer`, inserting the transfer ID into `finalised_transfers`.
5. `send_tokens` (line 2102) issues `ft_transfer(alice.near, 1000 USDC)` on the USDC token contract.
6. The USDC token contract panics because `alice.near` is blacklisted. The promise result is `Failed`.
7. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
8. `is_refund_required(false)` returns `false` without reading the promise result (line 1800–1802).
9. The callback enters the `else` branch: mints fee tokens to the relayer, emits `FinTransferEvent`.
10. The transfer ID remains in `finalised_transfers`; any retry of the same proof is rejected with `ERR_TRANSFER_ALREADY_FINALISED`.
11. 1000 USDC remain locked in the bridge contract. Alice receives nothing. Funds are permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L2102-2106)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
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

**File:** near/omni-bridge/src/lib.rs (L2322-2333)
```rust
    fn remove_fin_transfer(&mut self, transfer_id: &TransferId, storage_owner: &AccountId) {
        let storage_usage = env::storage_usage();
        self.finalised_transfers.remove(transfer_id);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(storage_owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(storage_owner, &storage);
        }
    }
```
