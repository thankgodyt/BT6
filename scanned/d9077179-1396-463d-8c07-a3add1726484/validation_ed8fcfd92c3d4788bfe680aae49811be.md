### Title
`remove_fin_transfer()` Clears Replay Protection on Failed `ft_transfer_call`, Enabling Inbound Transfer Replay — (`File: near/omni-bridge/src/lib.rs`)

### Summary
When an inbound `fin_transfer` to a NEAR recipient contract fails because the recipient's `ft_on_transfer` rejects the tokens (returns 0), the bridge calls `remove_fin_transfer()`, which deletes the `TransferId` from `finalised_transfers`. This is the **only** replay-protection record for that inbound proof. After deletion, the same proof can be re-submitted, causing tokens to be minted or unlocked a second time.

### Finding Description
The NEAR bridge contract uses `finalised_transfers: LookupSet<TransferId>` as its sole replay guard for inbound transfers. When a finalized transfer is delivered via `ft_transfer_call` and the recipient contract rejects it (returns `0` from `ft_on_transfer`), the callback `fin_transfer_send_tokens_callback` determines a refund is required and calls `remove_fin_transfer`, which removes the `TransferId` from `finalised_transfers`. [1](#0-0) 

```rust
if Self::is_refund_required(is_ft_transfer_call) {
    self.burn_tokens_if_needed(...);
    self.revert_lock_actions(&lock_actions);
    self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);
    ...
}
```

`remove_fin_transfer` unconditionally removes the entry: [2](#0-1) 

`is_refund_required` returns `true` when `is_ft_transfer_call` is `true` and the promise result shows the recipient returned `0` (i.e., rejected the transfer): [3](#0-2) 

After `remove_fin_transfer` executes, the `TransferId` is no longer in `finalised_transfers`. The prover contracts do not maintain their own used-proof registry — that is the bridge contract's responsibility via `finalised_transfers`. The same proof can therefore be re-submitted to the prover and re-finalized. [4](#0-3) 

### Impact Explanation
**Critical.** For bridged (deployed) tokens: `burn_tokens_if_needed` burns the returned tokens, then on replay `fin_transfer` mints a fresh batch — **unauthorized minting**. For native (locked) tokens: `burn_tokens_if_needed` is a no-op, the tokens are returned to the bridge by the NEP-141 refund mechanism, and on replay they are transferred out again — **double-spend**. The attacker receives the same bridged value an unbounded number of times, draining the bridge's token supply or locked reserves. [5](#0-4) 

### Likelihood Explanation
**High.** The attacker only needs to:
1. Control a NEAR contract that is the designated recipient of a cross-chain transfer.
2. Ensure the transfer message has a non-empty `msg` field (so `is_ft_transfer_call = true`), which is set by the sender on the foreign chain — fully attacker-controlled.
3. Return `0` from `ft_on_transfer` to trigger the refund path.

No privileged access, no key compromise, and no external dependency failure is required. Any user who can initiate a cross-chain transfer and control the recipient contract on NEAR can execute this attack.

### Recommendation
Do **not** remove the `TransferId` from `finalised_transfers` on failure. The replay-protection record must be permanent regardless of whether token delivery succeeded. If retry semantics are desired, track the failure separately (e.g., a `failed_transfers` map) and allow re-delivery attempts without clearing the finalization record. The nonce must never become reusable once a valid proof has been accepted.

### Proof of Concept
1. Attacker deploys a malicious NEAR contract `evil.near` whose `ft_on_transfer` always returns the full amount (rejects all tokens).
2. Attacker initiates a transfer from Ethereum to `evil.near` with a non-empty `msg` field, locking 1000 USDC on the EVM side.
3. Relayer submits the EVM event proof to the NEAR prover; `fin_transfer` is called, `TransferId{Eth, nonce=42}` is inserted into `finalised_transfers`, and 1000 USDC is minted and sent via `ft_transfer_call` to `evil.near`.
4. `evil.near.ft_on_transfer` returns `1000` (full amount), triggering `is_refund_required = true`.
5. `fin_transfer_send_tokens_callback` calls `burn_tokens_if_needed` (burns the 1000 USDC) and then `remove_fin_transfer`, deleting `TransferId{Eth, nonce=42}` from `finalised_transfers`.
6. Relayer (or attacker) re-submits the same proof. `add_fin_transfer` succeeds (nonce not in set), 1000 USDC is minted again and sent to `evil.near`.
7. This time `evil.near` accepts the tokens (returns `0`). Attacker now holds 1000 USDC despite the original 1000 USDC having been burned in step 5 — net gain of 1000 USDC from nothing.
8. Steps 3–7 can be repeated with the same proof indefinitely. [2](#0-1) [1](#0-0)

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

**File:** near/omni-bridge/src/lib.rs (L1806-1813)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
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
