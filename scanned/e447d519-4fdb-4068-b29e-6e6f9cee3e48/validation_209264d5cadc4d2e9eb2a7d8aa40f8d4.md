### Title
`fin_transfer_send_tokens_callback` Removes Finalization Record on `ft_transfer_call` Refund, Enabling Proof Replay and Double-Minting — (File: `near/omni-bridge/src/lib.rs`)

### Summary

When a `fin_transfer` to a NEAR recipient uses `ft_transfer_call` (triggered by a non-empty `msg` field) and the recipient contract's `ft_on_transfer` returns `0` (requesting a full refund), `fin_transfer_send_tokens_callback` calls `remove_fin_transfer`, which **deletes the transfer ID from `finalised_transfers`**. This is the sole replay-protection record for that cross-chain transfer. Once removed, the same foreign-chain proof can be re-submitted to `fin_transfer`, causing the bridge to mint or release tokens a second time for the same origin event.

---

### Finding Description

**Entry path:**

1. A user initiates a transfer on a foreign chain (EVM, Solana, etc.) with a non-empty `msg` field and sets the NEAR recipient to a contract they control.
2. A trusted relayer calls `fin_transfer()` with the valid proof.
3. `fin_transfer_callback` → `process_fin_transfer_to_near` is invoked.

**Step 1 — Finalization record written:**

`process_fin_transfer_to_near` immediately calls `add_fin_transfer`, which inserts the `TransferId` into `finalised_transfers` (the only replay guard): [1](#0-0) [2](#0-1) 

**Step 2 — Tokens sent via `ft_transfer_call`:**

Because `msg` is non-empty, `send_tokens` uses `ft_transfer_call`, which invokes `ft_on_transfer` on the recipient contract: [3](#0-2) 

**Step 3 — Malicious recipient returns `0`:**

The attacker's NEAR contract returns `0` from `ft_on_transfer`. Under NEP-141, this signals that the full transferred amount is unused and should be refunded to the bridge. `ft_transfer_call` therefore returns `0` to the bridge's callback.

**Step 4 — Finalization record deleted:**

`fin_transfer_send_tokens_callback` detects the refund via `is_refund_required` (which returns `true` when `ft_transfer_call` returns `0`), then calls `remove_fin_transfer`: [4](#0-3) [5](#0-4) 

`remove_fin_transfer` unconditionally removes the `TransferId` from `finalised_transfers`. No other state records that this proof was ever processed.

**Step 5 — Proof replayed:**

The same foreign-chain proof is now re-submittable. `add_fin_transfer` will succeed again (the set no longer contains the ID), and the bridge will mint or release tokens a second time. The cycle can repeat indefinitely.

---

### Impact Explanation

**For bridge-deployed (mintable) tokens:**
- Bridge mints tokens → recipient refunds → bridge burns refunded tokens → finalization record deleted → same proof re-submitted → bridge mints again → unlimited token inflation.

**For native locked tokens:**
- Bridge unlocks and sends tokens → recipient refunds → `revert_lock_actions` re-locks them → finalization record deleted → same proof re-submitted → bridge unlocks and sends again → double-spending from the locked pool.

Both paths allow an attacker to drain or inflate bridged token supply with no limit, constituting a critical loss of funds.

---

### Likelihood Explanation

Any user who can initiate a cross-chain transfer (permissionless on all supported foreign chains) and who controls a NEAR contract address can trigger this:

1. Deploy a NEAR contract whose `ft_on_transfer` always returns `0`.
2. Initiate a transfer from a foreign chain with a non-empty `msg` and that contract as recipient.
3. After a relayer finalizes the transfer and the refund removes the record, re-submit the same proof (or wait for an automated relayer to retry, which is standard relayer behavior when a transfer appears un-finalized).

No privileged access beyond being a trusted relayer (or having a trusted relayer retry) is required for step 3. Automated relayers that monitor `finalised_transfers` would naturally retry a transfer whose ID is absent.

---

### Recommendation

Do **not** remove the `TransferId` from `finalised_transfers` when a refund is required. The finalization record must be permanent regardless of whether the downstream `ft_transfer_call` succeeded or failed. If the transfer needs to be retried with different parameters (e.g., a different recipient or empty `msg`), a separate mechanism (e.g., a dedicated retry entry-point that does not re-verify the proof) should be used. The analog fix from the external report applies directly: once a transfer is finalized, that state must be irreversible.

```rust
// In fin_transfer_send_tokens_callback, remove this line:
self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);
```

---

### Proof of Concept

1. Deploy malicious NEAR contract `evil.near` with `ft_on_transfer` returning `0`.
2. On Ethereum, call `OmniBridge.initTransfer(token, amount, fee, "evil.near", "trigger")` — the non-empty `"trigger"` string ensures `ft_transfer_call` is used on NEAR.
3. Relayer submits `fin_transfer` with the Ethereum proof. Bridge calls `add_fin_transfer` (ID inserted), mints tokens, calls `ft_transfer_call("evil.near", amount, "trigger")`.
4. `evil.near::ft_on_transfer` returns `0`. Tokens refunded to bridge. Bridge calls `fin_transfer_send_tokens_callback` → `is_refund_required` = `true` → `burn_tokens_if_needed` burns refunded tokens → `remove_fin_transfer` deletes the ID.
5. Relayer (or attacker acting as relayer) re-submits the identical Ethereum proof to `fin_transfer`. `add_fin_transfer` succeeds (ID absent). Bridge mints tokens again. Repeat from step 4. [6](#0-5) [7](#0-6) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1692-1718)
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

**File:** near/omni-bridge/src/lib.rs (L1783-1803)
```rust
impl Contract {
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

**File:** near/omni-bridge/src/lib.rs (L2226-2231)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
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
