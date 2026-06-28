### Title
Relayer's Fronted Tokens Permanently Lost When `send_tokens().detach()` Fails During Fast Transfer Finalization - (File: `near/omni-bridge/src/lib.rs`)

### Summary
In `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast`, the bridge irrevocably commits fast-transfer state (marking it finalised or removing it) and then fires the relayer-reimbursement token transfer with `.detach()` — no callback, no rollback. If the `ft_transfer` promise fails, the relayer who fronted tokens to the user permanently loses those funds with no recovery path.

### Finding Description

The fast-transfer flow lets a trusted relayer front tokens to a user before the cross-chain proof arrives. When the proof is later submitted via `fin_transfer`, the bridge is supposed to reimburse the relayer.

**Path 1 — `process_fin_transfer_to_other_chain` (EVM/Solana → other-chain fast transfer)** [1](#0-0) 

The sequence inside the `if let Some(relayer) = recipient` branch is:
1. `send_tokens(token, relayer, amount, "").detach()` — promise is scheduled but **no callback is registered**.
2. `mark_fast_transfer_as_finalised(&fast_transfer.id())` — state is committed synchronously in the same transaction.

`add_fin_transfer` was already called at the top of the function, inserting the transfer ID into `finalised_transfers`: [2](#0-1) 

No pending transfer is added to `pending_transfers` in the fast-transfer branch (only the `else` branch adds one): [3](#0-2) 

**Path 2 — `utxo_fin_transfer_fast` (BTC/Zcash fast transfer)** [4](#0-3) 

When `destination == Near`, `remove_fast_transfer` is called **before** `send_tokens().detach()`. When `destination != Near`, `mark_fast_transfer_as_finalised` is called before the detached send. In both sub-cases the state is committed before the promise executes.

The developers themselves flagged this as unresolved: [5](#0-4) 

**Why recovery is impossible after failure**

If the detached `ft_transfer` fails:

- `finalised_transfers` already contains the transfer ID → a retry of `fin_transfer` panics with `ERR_TRANSFER_ALREADY_FINALISED` via `add_fin_transfer`: [6](#0-5) 

- The fast transfer is either removed or marked `finalised = true` → any re-entry into `process_fin_transfer_to_near`, `process_fin_transfer_to_other_chain`, or `utxo_fin_transfer_fast` panics with `ERR_FAST_TRANSFER_ALREADY_FINALISED`: [7](#0-6) 

- No pending transfer was inserted into `pending_transfers` → `claim_fee_callback` cannot find the transfer and panics with `ERR_TRANSFER_NOT_EXIST`: [8](#0-7) 

The relayer's fronted tokens remain locked inside the bridge contract indefinitely.

### Impact Explanation

A trusted relayer who executed a fast transfer fronts their own tokens to the user. If the reimbursement `ft_transfer` fails during `fin_transfer` finalization, those tokens are permanently frozen inside the bridge contract. There is no admin escape hatch, no retry function, and no `claim_fee` path that applies to this state. This constitutes permanent loss of bridged funds.

### Likelihood Explanation

The `ft_transfer` can fail in realistic conditions:
- The relayer's account is not registered for the specific token (storage deposit not made for that token contract). This is plausible for newly deployed bridge tokens.
- The token contract is paused or temporarily unavailable at the moment `fin_transfer` is processed.
- Insufficient gas is forwarded to the detached promise (the `send_tokens` function subtracts `SEND_TOKENS_CALLBACK_GAS` from remaining gas even though no callback is used in this path, potentially leaving too little gas for the actual transfer): [9](#0-8) 

### Recommendation

Replace `.detach()` with a proper callback in both `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast`. The callback should detect failure and either:
1. Revert the fast-transfer state (un-finalise / re-insert the record) so the relayer can retry, or
2. Store the owed amount in a claimable mapping that the relayer can withdraw later.

The pattern used in `process_fin_transfer_to_near` — which chains `send_tokens` to `fin_transfer_send_tokens_callback` and reverts lock actions on failure — is the correct model to follow: [10](#0-9) 

### Proof of Concept

1. Relayer R executes a fast transfer for cross-chain transfer T (EVM → Solana), fronting tokens to the user on NEAR.
2. R calls `fin_transfer` with the EVM proof. `process_fin_transfer_to_other_chain` is entered.
3. `add_fin_transfer` inserts T into `finalised_transfers`.
4. A fast transfer status is found; `send_tokens(token, R, amount, "").detach()` is scheduled.
5. `mark_fast_transfer_as_finalised` commits `finalised = true` for the fast transfer.
6. The detached `ft_transfer` promise fails (e.g., R has no storage deposit for the token).
7. R attempts to retry `fin_transfer` → panics `ERR_TRANSFER_ALREADY_FINALISED`.
8. R attempts `claim_fee` → panics `ERR_TRANSFER_NOT_EXIST` (no pending transfer was added).
9. R's fronted tokens remain permanently locked in the bridge contract.

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L1985-1985)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
```

**File:** near/omni-bridge/src/lib.rs (L2009-2013)
```rust
        let recipient = if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            require!(
                !status.finalised,
                BridgeError::FastTransferAlreadyFinalised.as_ref()
            );
```

**File:** near/omni-bridge/src/lib.rs (L2027-2040)
```rust
        // If fast transfer happened, send tokens to the relayer that executed fast transfer
        if let Some(relayer) = recipient {
            self.send_tokens(
                token,
                relayer,
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
                "",
            )
            .detach();
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
```

**File:** near/omni-bridge/src/lib.rs (L2041-2044)
```rust
        } else {
            required_balance = self
                .add_transfer_message(transfer_message.clone(), predecessor_account_id.clone())
                .saturating_add(required_balance);
```

**File:** near/omni-bridge/src/lib.rs (L2063-2067)
```rust
        let ft_transfer_call_gas = env::prepaid_gas()
            .saturating_sub(env::used_gas())
            .saturating_sub(SEND_TOKENS_CALLBACK_GAS) // TODO: not all send_tokens callbacks has the same gas.
            .saturating_sub(MINT_TOKEN_GAS)
            .min(FT_TRANSFER_CALL_GAS);
```

**File:** near/omni-bridge/src/lib.rs (L2194-2200)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);
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

**File:** near/omni-bridge/src/lib.rs (L2484-2485)
```rust
            // TODO: check how to deal with failed send_tokens
            return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
```

**File:** near/omni-bridge/src/lib.rs (L2529-2548)
```rust
        let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
            self.remove_fast_transfer(&fast_transfer.id());
            fast_transfer.amount
        } else {
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
            // With transfers to other chain the fee will be claimed after finalization on the destination chain
            U128(
                fast_transfer
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            )
        };

        self.send_tokens(
            fast_transfer.token_id.clone(),
            fast_transfer_status.relayer,
            amount,
            "",
        )
        .detach();
```
