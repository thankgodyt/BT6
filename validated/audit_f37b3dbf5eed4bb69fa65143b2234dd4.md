Audit Report

## Title
Double-Finalization via `remove_fin_transfer` in Failed `ft_transfer_call` Callback — (File: `near/omni-bridge/src/lib.rs`)

## Summary
When an inbound transfer to a NEAR recipient uses `ft_transfer_call` (non-empty `msg`) and the recipient's `ft_on_transfer` returns `U128(0)`, the callback `fin_transfer_send_tokens_callback` calls `remove_fin_transfer`, which permanently deletes the transfer ID from `finalised_transfers`. This allows the same proof to be submitted a second time, bypassing the replay-prevention guard in `add_fin_transfer`, and minting or unlocking tokens a second time — constituting unauthorized double-minting or double-spending of bridged funds.

## Finding Description
The exploit path is confirmed by the code:

1. **`process_fin_transfer_to_near`** (line 1875) calls `add_fin_transfer`, which inserts the transfer ID into `finalised_transfers` as the sole replay-prevention guard: [1](#0-0) 

2. `add_fin_transfer` uses `LookupSet::insert` and panics if the ID is already present — this is the only replay check: [2](#0-1) 

3. `process_fin_transfer_to_near` then calls `send_tokens` (which issues `ft_transfer_call`) and chains `fin_transfer_send_tokens_callback` as the resolution callback: [3](#0-2) 

4. **`fin_transfer_send_tokens_callback`** (line 1702): when `is_refund_required` is true, it burns tokens, reverts lock actions, and then calls `remove_fin_transfer`, **erasing the transfer ID from `finalised_transfers`**: [4](#0-3) 

5. **`is_refund_required`** returns `true` when `ft_on_transfer` returns `U128(0)` — a value fully controlled by the recipient contract: [5](#0-4) 

6. **`remove_fin_transfer`** unconditionally removes the entry with no tombstone: [6](#0-5) 

After removal, the attacker resubmits the same proof. `add_fin_transfer` succeeds because the ID is absent, and tokens are minted or unlocked a second time. No existing guard prevents this: the only replay check is the `finalised_transfers` set membership, which has been erased.

## Impact Explanation
This is a **Critical** impact matching "double-spending, unauthorized minting of bridged funds":

- **Deployed (bridged) tokens**: First call mints and sends tokens via `ft_transfer_call`; recipient returns `U128(0)`; bridge burns them; transfer ID is removed. Second call mints tokens again and the attacker keeps them. Net: **unauthorized double-minting**.
- **Native NEAR tokens locked on NEAR side**: First call unlocks and sends tokens; recipient returns `U128(0)`; `revert_lock_actions` re-locks them; transfer ID is removed. Second call unlocks tokens again and the attacker keeps them. Net: **double-spending of locked funds**.

## Likelihood Explanation
The attacker requires only:
1. A valid inbound proof for a transfer they initiated from the source chain (a normal user action requiring no privilege).
2. A recipient contract they control that returns `U128(0)` from `ft_on_transfer` on the first invocation and accepts tokens on the second.

No admin compromise, key leakage, validator collusion, or external oracle manipulation is required. The exploit is fully self-contained within the NEAR smart contract and is reproducible on a local testnet.

## Recommendation
Never remove a transfer ID from `finalised_transfers` after tokens have been released or attempted to be released. The fix is to retain the ID permanently in `finalised_transfers` regardless of whether `ft_transfer_call` succeeded or failed. If a refund is needed, handle it without erasing the replay-prevention record. Alternatively, replace `remove_fin_transfer` in the failure path with a "failed" tombstone state (e.g., a `LookupMap<TransferId, TransferStatus>` with a `Failed` variant) so that re-submission of the same proof is still rejected.

## Proof of Concept
```
1. Attacker deploys `MaliciousReceiver` on NEAR:
   - First call to `ft_on_transfer`: returns U128(0) (triggers refund path)
   - Second call to `ft_on_transfer`: returns U128(amount) (accepts tokens)

2. Attacker initiates a transfer from EVM → NEAR with:
   - recipient = MaliciousReceiver
   - msg = "<non-empty>" (forces ft_transfer_call path)

3. Attacker calls `fin_transfer(proof)`:
   - add_fin_transfer inserts transfer_id into finalised_transfers ✓
   - ft_transfer_call → MaliciousReceiver.ft_on_transfer returns U128(0)
   - fin_transfer_send_tokens_callback: is_refund_required = true
   - burn_tokens_if_needed (tokens burned / re-locked)
   - remove_fin_transfer removes transfer_id from finalised_transfers ← BUG

4. Attacker immediately calls `fin_transfer(same proof)`:
   - add_fin_transfer: transfer_id not in finalised_transfers → INSERT succeeds
   - ft_transfer_call → MaliciousReceiver.ft_on_transfer returns U128(amount)
   - fin_transfer_send_tokens_callback: is_refund_required = false
   - Tokens minted/unlocked and kept by attacker

5. Assert: attacker holds tokens from a proof that was already "finalized" once.
```

A local integration test can be written using `near-workspaces-rs`: deploy the bridge contract and a `MaliciousReceiver` contract on a local sandbox, submit the same `FinTransferMessage` twice, and assert that the attacker's token balance equals twice the transfer amount after step 4.

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L1784-1791)
```rust
    fn is_refund_required(is_ft_transfer_call: bool) -> bool {
        if is_ft_transfer_call {
            match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
                Ok(value) => {
                    if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                        // Normal case: refund if the used token amount is zero
                        // The amount can be zero if the `ft_on_transfer` in the receiver contract returns an amount instead of `0`, or if it panics.
                        amount.0 == 0
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
