### Title
No Cancel/Refund Mechanism for Stuck Pending Transfers Causes Permanent Loss of Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates a cross-chain transfer via `init_transfer`, their tokens are immediately and irreversibly burned (for deployed/bridge-minted tokens) or locked inside the bridge contract (for native tokens). If the resulting pending transfer entry in `pending_transfers` can never be finalized — for example because the token address is not registered for the destination chain, causing every `sign_transfer` call to panic — there is no cancel, refund, or timeout mechanism. The user's funds are permanently lost with no recovery path, directly analogous to the Sablier MerkleLockup clawback issue.

---

### Finding Description

**Step 1 — Tokens are burned/locked before any finalizability check.**

In `init_transfer_internal`, the bridge immediately burns deployed tokens and locks non-deployed tokens, then inserts the transfer into `pending_transfers`: [1](#0-0) 

`burn_tokens_if_needed` fires a detached cross-contract call that cannot be rolled back: [2](#0-1) 

**Step 2 — `sign_transfer` panics if the token address is not registered for the destination chain.**

`sign_transfer` calls `get_token_address` and panics with `FailedToGetTokenAddress` if the mapping is absent: [3](#0-2) 

Because `init_transfer` does **not** verify that the token is registered for the chosen destination chain before burning/locking, a user can reach a state where their tokens are already gone but `sign_transfer` will always panic.

**Step 3 — `sign_transfer_callback` does not remove the pending transfer on signing failure.**

When the MPC signing call fails, the callback silently returns without touching `pending_transfers`: [4](#0-3) 

Even on success, the transfer is only removed when `fee.is_zero()`. For non-zero-fee transfers the entry persists until `claim_fee` is called.

**Step 4 — `claim_fee` requires a proof from the destination chain that can never arrive.**

`claim_fee` removes the pending transfer only after verifying a destination-chain proof: [5](#0-4) 

If the destination chain never finalizes the transfer (wrong token address, wrong factory, paused contract, etc.), no proof is ever produced and `claim_fee` can never be called.

**Step 5 — No public cancel/refund function exists.**

Searching the entire contract, `remove_transfer_message` is only reachable through:
- `sign_transfer_callback` (fee-zero path, signing must succeed)
- `claim_fee_callback` (requires destination-chain proof)
- `remove_transfer_message_without_refund` inside `init_transfer_internal` (storage-failure path only) [6](#0-5) 

There is no timeout, expiration, or user-callable cancel function. The `pending_transfers` map has no TTL: [7](#0-6) 

---

### Impact Explanation

For **deployed (bridge-minted) tokens**: the tokens are burned at `init_transfer` time. If the transfer is permanently stuck, those tokens are destroyed with no mint-back path. This is a direct, irreversible loss of bridged funds.

For **non-deployed (native) tokens**: the tokens are held by the bridge contract and tracked in `locked_tokens`. A stuck transfer permanently freezes those tokens inside the bridge with no withdrawal path for the user.

Both outcomes fall squarely within the allowed critical impact: *permanent freezing or loss of bridged funds*.

---

### Likelihood Explanation

The trigger is reachable by any unprivileged bridge user:

1. A user calls `ft_transfer_call` targeting the bridge with a destination chain for which the token address mapping (`token_id_to_address`) has not been registered via `bind_token` or `deploy_token`.
2. `init_transfer_internal` burns/locks the tokens and inserts the pending entry.
3. Every subsequent `sign_transfer` call panics; the entry is immortal.

No admin compromise, no relayer collusion, and no external dependency failure is required. The user alone can reach this state by choosing a destination chain/token combination that is not yet (or incorrectly) configured. Given that the bridge supports multiple chains and tokens are added incrementally, this is a realistic operational scenario.

---

### Recommendation

1. **Pre-flight check in `init_transfer`**: Before burning/locking tokens, verify that `get_token_address` returns a non-None value for the chosen destination chain. Revert and refund if the mapping is absent.
2. **User-callable cancel with grace period**: Add a public `cancel_transfer(transfer_id)` function that allows the original sender to cancel a pending transfer and recover their tokens, callable only after a configurable timeout (e.g., 7 days) from the time the transfer was created — mirroring the Sablier fix.
3. **Timestamp in `TransferMessageStorage`**: Record the creation timestamp so the grace period can be enforced on-chain.

---

### Proof of Concept

```
1. Token `wETH.near` is a deployed (bridge-minted) token.
   Its address is registered for ChainKind::Eth but NOT for ChainKind::Sol.

2. User calls:
     wETH.near::ft_transfer_call(
       receiver_id = omni-bridge.near,
       amount      = 1_000_000,
       msg         = InitTransfer { recipient: Sol(<address>), fee: 100, ... }
     )

3. omni-bridge::ft_on_transfer → init_transfer → init_transfer_internal:
   - burn_tokens_if_needed fires: 1_000_000 wETH burned (detached, irreversible).
   - pending_transfers.insert(transfer_id, ...) succeeds.
   - Returns U128(0) — user receives no refund.

4. Relayer calls omni-bridge::sign_transfer(transfer_id, ...):
   - get_token_address(ChainKind::Sol, wETH.near) → None
   - env::panic_str("ERR_FAILED_TO_GET_TOKEN_ADDRESS")
   - Transaction reverted; pending_transfers entry survives.

5. Step 4 repeats forever. No cancel function exists.
   1_000_000 wETH are permanently destroyed.
   The user has no recourse.
```

### Citations

**File:** near/omni-bridge/src/lib.rs (L222-222)
```rust
    pub pending_transfers: LookupMap<TransferId, TransferMessageStorage>,
```

**File:** near/omni-bridge/src/lib.rs (L462-469)
```rust
        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });
```

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
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

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
```

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```
