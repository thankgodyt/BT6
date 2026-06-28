### Title
Failed `fin_transfer` Removes Replay Protection, Enabling Proof Replay and Double-Minting — (File: near/omni-bridge/src/lib.rs)

### Summary

When a `fin_transfer` to a NEAR recipient fails because the recipient's `ft_on_transfer` rejects the tokens (returning 0 used), `fin_transfer_send_tokens_callback` calls `remove_fin_transfer`, which **deletes the `TransferId` from `finalised_transfers`**. This erases the only replay guard for that source-chain event, allowing the identical proof to be submitted again. A single on-chain `InitTransfer` event on the source chain can therefore cause multiple NEAR-side token mints or unlocks.

### Finding Description

The NEAR omni-bridge uses `finalised_transfers: LookupSet<TransferId>` as its sole replay-protection store for inbound transfers destined for NEAR. The `TransferId` is `(origin_chain, origin_nonce)`, derived directly from the source-chain event.

**Step 1 — Replay guard is set:**
`process_fin_transfer_to_near` calls `add_fin_transfer` which inserts the `TransferId` and panics if it already exists. [1](#0-0) [2](#0-1) 

**Step 2 — Token delivery is attempted via `ft_transfer_call`:**
When the transfer message carries a non-empty `msg`, `send_tokens` issues an `ft_transfer_call` (or `mint` with a message for deployed tokens). The result is inspected in `is_refund_required`. [3](#0-2) [4](#0-3) 

**Step 3 — On failure, the replay guard is deleted:**
If `is_refund_required` returns `true` (the `ft_transfer_call` result is 0, meaning the recipient consumed no tokens), `fin_transfer_send_tokens_callback` calls `remove_fin_transfer`, which removes the `TransferId` from `finalised_transfers`. [5](#0-4) [6](#0-5) 

**Step 4 — The same proof is now replayable:**
Because `finalised_transfers` no longer contains the `TransferId`, a subsequent call to `fin_transfer` with the identical Borsh-encoded proof passes `add_fin_transfer` without reverting. A new `destination_nonce` is assigned (but for NEAR-destined transfers `get_next_destination_nonce` always returns 0, providing no additional protection), and the bridge mints or unlocks tokens a second time. [7](#0-6) 

### Impact Explanation

A single source-chain `InitTransfer` event (which locked or burned tokens exactly once on the origin chain) can cause the NEAR bridge to mint or unlock the same token amount multiple times. This breaks the fundamental bridge invariant of 1:1 asset backing, constitutes unauthorized minting / escrow mis-accounting, and directly causes loss of funds for the protocol (unbacked tokens circulate on NEAR).

### Likelihood Explanation

`fin_transfer` is gated by `#[trusted_relayer]`, so the replaying caller must hold a trusted-relayer role. [8](#0-7) 

However, the trigger condition — a recipient contract whose `ft_on_transfer` transiently rejects tokens — is realistic for any contract with conditional acceptance logic (e.g., a DEX router, a vault with capacity limits, or a contract under maintenance). A legitimate relayer retrying a failed transfer is the natural, non-malicious path to exploitation. Any trusted relayer (including one acting in good faith) who resubmits the same proof after conditions change causes the double-mint.

### Recommendation

Do **not** remove the `TransferId` from `finalised_transfers` on failure. The replay guard must be permanent regardless of whether the downstream token delivery succeeded. If a retry with different `storage_deposit_actions` is desired, track the failure state separately (e.g., a `failed_transfers` map) and allow the relayer to re-attempt delivery without re-verifying the proof. This mirrors the fix applied in the referenced Rolla report: the nonce (here, the finalised-transfer entry) must survive failed executions. [9](#0-8) 

### Proof of Concept

1. Alice initiates a transfer of 10,000 USDC from Ethereum to a NEAR recipient contract `receiver.near` that implements `ft_on_transfer` with a capacity check (rejects when its internal balance exceeds a threshold).
2. Relayer calls `fin_transfer` with the valid EVM proof. `add_fin_transfer` inserts `TransferId{Eth, nonce=42}` into `finalised_transfers`. The bridge mints 10,000 USDC and calls `ft_transfer_call` → `receiver.near::ft_on_transfer` → rejects (capacity full), returns full amount unused.
3. `is_refund_required` returns `true`. `fin_transfer_send_tokens_callback` burns the minted tokens and calls `remove_fin_transfer`, deleting `TransferId{Eth, nonce=42}` from `finalised_transfers`.
4. `receiver.near` drains its balance (capacity now available).
5. Relayer (or attacker with trusted-relayer role) resubmits the identical proof. `add_fin_transfer` succeeds (entry was deleted). Bridge mints another 10,000 USDC and delivers them to `receiver.near`.
6. Result: 20,000 USDC minted on NEAR from a single 10,000 USDC lock on Ethereum. The bridge is 10,000 USDC under-collateralised. [10](#0-9) [2](#0-1)

### Citations

**File:** near/omni-bridge/src/lib.rs (L670-673)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
```

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

**File:** near/omni-bridge/src/lib.rs (L1815-1827)
```rust
    fn get_next_destination_nonce(&mut self, chain_kind: ChainKind) -> Nonce {
        if chain_kind == ChainKind::Near {
            return 0;
        }

        let mut payload_nonce = self.destination_nonces.get(&chain_kind).unwrap_or_default();

        payload_nonce += 1;

        self.destination_nonces.insert(&chain_kind, &payload_nonce);

        payload_nonce
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
