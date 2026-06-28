### Title
Replay of `fin_transfer` Proof After Recipient-Rejection Refund Enables Double-Spend — (`File: near/omni-bridge/src/lib.rs`)

### Summary

When a `fin_transfer` to a NEAR recipient uses `ft_transfer_call` (non-empty `msg`) and the recipient contract rejects the tokens (returns the full amount from `ft_on_transfer`), `fin_transfer_send_tokens_callback` calls `remove_fin_transfer`, which **deletes the transfer ID from `finalised_transfers`** — the sole replay-protection set for inbound proofs. The same foreign-chain proof can then be submitted a second time, minting or unlocking tokens a second time for a single on-chain event.

### Finding Description

The inbound finalization flow for a NEAR-recipient transfer is:

1. `fin_transfer` → `fin_transfer_callback` → `process_fin_transfer_to_near`
2. `add_fin_transfer` inserts the `TransferId` into `finalised_transfers` (replay guard).
3. `send_tokens` issues `ft_transfer_call` when `msg` is non-empty.
4. `fin_transfer_send_tokens_callback` is invoked as the callback.

Inside `fin_transfer_send_tokens_callback`, when `is_refund_required` returns `true` (the recipient's `ft_on_transfer` returned 0, meaning it used 0 tokens / rejected all):

```rust
// near/omni-bridge/src/lib.rs  lines 1702-1718
if Self::is_refund_required(is_ft_transfer_call) {
    self.burn_tokens_if_needed(...);
    self.revert_lock_actions(&lock_actions);
    self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);
    // emits FailedFinTransferEvent
}
```

`remove_fin_transfer` unconditionally removes the entry:

```rust
// near/omni-bridge/src/lib.rs  lines 2322-2332
fn remove_fin_transfer(&mut self, transfer_id: &TransferId, storage_owner: &AccountId) {
    let storage_usage = env::storage_usage();
    self.finalised_transfers.remove(transfer_id);
    // ...
}
```

After removal, `add_fin_transfer` will succeed again for the same `TransferId`:

```rust
// near/omni-bridge/src/lib.rs  lines 2226-2234
fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
    require!(
        self.finalised_transfers.insert(transfer_id),
        BridgeError::TransferAlreadyFinalised.as_ref()
    );
    // ...
}
```

The prover verifies the cryptographic proof against the light-client state; it does not track which proofs have already been consumed. `finalised_transfers` is the only replay barrier. Once it is cleared, the identical proof bytes are accepted a second time.

### Impact Explanation

An attacker who controls the NEAR recipient contract can:

1. Initiate a transfer on the EVM side with a non-empty `msg` and the malicious NEAR contract as recipient.
2. A relayer submits the proof via `fin_transfer`. Tokens are minted/unlocked and sent via `ft_transfer_call`.
3. The malicious `ft_on_transfer` returns the full amount (rejects). `remove_fin_transfer` clears the replay guard. `FailedFinTransferEvent` is emitted.
4. The relayer (or the attacker if they hold `UnrestrictedRelayer`) re-submits the same proof (a natural retry after observing the failure event).
5. `add_fin_transfer` succeeds. Tokens are minted/unlocked a second time and delivered to the attacker's contract, which now accepts them.

Result: **two token deliveries for one foreign-chain lock event** — unauthorized minting (deployed tokens) or double-unlock (native tokens), permanently inflating supply or draining the bridge escrow.

### Likelihood Explanation

- The attacker controls the recipient address and `msg` field when initiating the transfer on the EVM side — both are user-supplied inputs.
- The `FailedFinTransferEvent` log is a natural signal for relayers to retry, making the second submission likely without any social engineering.
- No admin compromise, key leak, or MPC collusion is required.

### Recommendation

Do **not** remove the `finalised_transfers` entry on a failed token delivery. The entry records that the foreign-chain event was consumed; that fact is permanent regardless of what happens on the NEAR side. Instead:

- Keep the `finalised_transfers` entry intact on refund.
- If the token delivery fails, record the failure separately (e.g., a `failed_transfers` set) and allow the user to claim a refund through a separate, authenticated path that does not re-accept the original proof.

### Proof of Concept

**Setup:**
- Deploy a malicious NEAR contract `evil.near` whose `ft_on_transfer` returns the full `amount` on the first call and `0` on the second call.
- Initiate a transfer on EVM: `recipient = "evil.near"`, `msg = "trigger_ft_transfer_call"` (non-empty).

**Step 1 — First `fin_transfer`:**

```
relayer → fin_transfer(proof)
  → fin_transfer_callback
    → process_fin_transfer_to_near
      → add_fin_transfer(transfer_id)          // finalised_transfers: {transfer_id}
      → send_tokens(ft_transfer_call, evil.near)
        → evil.near::ft_on_transfer returns amount  // reject
      → fin_transfer_send_tokens_callback
        → is_refund_required = true
        → remove_fin_transfer(transfer_id)     // finalised_transfers: {}  ← guard cleared
        → emits FailedFinTransferEvent
```

**Step 2 — Replay:**

```
relayer → fin_transfer(same proof)             // proof still valid against light client
  → fin_transfer_callback
    → process_fin_transfer_to_near
      → add_fin_transfer(transfer_id)          // succeeds! finalised_transfers: {transfer_id}
      → send_tokens(ft_transfer_call, evil.near)
        → evil.near::ft_on_transfer returns 0  // accept
      → fin_transfer_send_tokens_callback
        → is_refund_required = false
        → tokens delivered to evil.near        // DOUBLE SPEND
```

The attacker receives tokens twice for a single foreign-chain lock event. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L220-243)
```rust
pub struct Contract {
    pub factories: LookupMap<ChainKind, OmniAddress>,
    pub pending_transfers: LookupMap<TransferId, TransferMessageStorage>,
    pub finalised_transfers: LookupSet<TransferId>,
    pub finalised_utxo_transfers: LookupSet<UnifiedTransferId>,
    pub fast_transfers: LookupMap<FastTransferId, FastTransferStatusStorage>,
    pub token_id_to_address: LookupMap<(ChainKind, AccountId), OmniAddress>,
    pub token_address_to_id: LookupMap<OmniAddress, AccountId>,
    pub token_decimals: LookupMap<OmniAddress, Decimals>,
    pub deployed_tokens: LookupSet<AccountId>,
    pub deployed_tokens_v2: LookupMap<AccountId, ChainKind>,
    pub token_deployer_accounts: LookupMap<ChainKind, AccountId>,
    pub mpc_signer: AccountId,
    pub current_origin_nonce: Nonce,
    // We maintain a separate nonce for each chain to optimize the storage usage on Solana by reducing the gaps.
    pub destination_nonces: LookupMap<ChainKind, Nonce>,
    pub accounts_balances: LookupMap<AccountId, StorageBalance>,
    pub wnear_account_id: AccountId,
    pub provers: UnorderedMap<ChainKind, AccountId>,
    pub init_transfer_promises: LookupMap<AccountId, CryptoHash>,
    pub utxo_chain_connectors: HashMap<ChainKind, UTXOChainConfig>,
    pub migrated_tokens: LookupMap<AccountId, AccountId>,
    pub locked_tokens: LookupMap<(ChainKind, AccountId), u128>,
}
```

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

**File:** near/omni-bridge/src/lib.rs (L1874-1885)
```rust
    ) -> Promise {
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

**File:** near/omni-bridge/src/lib.rs (L2322-2332)
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
```
