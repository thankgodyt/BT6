### Title
Incomplete Locked-Token State Update in `process_fin_transfer_to_other_chain` During Fast Transfer Finalization Enables Double-Spending of Bridged Tokens - (File: `near/omni-bridge/src/lib.rs`)

### Summary

When a fast transfer to a non-NEAR chain is finalized, `process_fin_transfer_to_other_chain` pays the relayer `amount_without_fee` tokens but never unlocks the identical amount that was locked on the destination chain during `fast_fin_transfer_to_other_chain`. This permanently inflates `locked_tokens[destination_chain]`, allowing the bridge to later accept a return transfer from the destination chain for those same tokens — effectively paying out `amount_without_fee` twice while only holding one unit of Ethereum-side backing.

### Finding Description

**Step 1 — Fast transfer execution (`fast_fin_transfer_to_other_chain`):**

When a trusted relayer fronts a transfer to a non-NEAR destination (e.g., Solana), the bridge burns the relayer's deposited tokens and locks `amount_without_fee` on the destination chain to record its obligation:

```rust
self.burn_tokens_if_needed(fast_transfer.token_id.clone(), amount_without_fee.into());

self.lock_tokens_if_needed(
    fast_transfer.get_destination_chain(),
    &fast_transfer.token_id,
    amount_without_fee,          // ← locked on Sol
);
``` [1](#0-0) 

**Step 2 — Fast transfer finalization (`process_fin_transfer_to_other_chain`):**

When the Ethereum proof arrives and `fin_transfer_callback` is called, the bridge enters the fast-transfer branch. It unlocks from the origin chain (a no-op for Eth-origin tokens), locks only the fee on the destination chain, pays the relayer `amount_without_fee`, and marks the fast transfer as finalised — but **never unlocks the `amount_without_fee` that was locked in Step 1**:

```rust
self.unlock_tokens_if_needed(
    transfer_message.get_origin_chain(),   // Eth → no-op for Eth-origin tokens
    &token,
    transfer_message.amount.0,
);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token,
    transfer_message.fee.fee.into(),       // only fee is locked, NOT amount_without_fee
);

// fast transfer branch:
self.send_tokens(token, relayer, U128(amount_without_fee), "").detach();
self.mark_fast_transfer_as_finalised(&fast_transfer.id());
// ← amount_without_fee locked in Step 1 is NEVER unlocked
``` [2](#0-1) 

After fee claim (`send_fee_internal` unlocks only `fee.fee`): [3](#0-2) 

The permanent residual in `locked_tokens[Sol]` equals `amount_without_fee`.

**The `lock_tokens_if_needed` / `unlock_tokens_if_needed` mechanics:** [4](#0-3) 

`unlock_tokens` enforces `available >= amount` before decrementing. An inflated `locked_tokens[Sol]` therefore passes this check for a subsequent Sol→NEAR transfer that should not be permitted. [5](#0-4) 

**Step 3 — Victim's return transfer:**

The user on Solana legitimately holds `amount_without_fee` tokens (received from the relayer). They initiate a Sol→NEAR transfer. `process_fin_transfer_to_near` calls:

```rust
let lock_actions = vec![self.unlock_tokens_if_needed(
    transfer_message.get_origin_chain(),   // Sol
    &token,
    transfer_message.amount.0,             // amount_without_fee
)];
``` [6](#0-5) 

Because `locked_tokens[Sol]` is still `amount_without_fee`, the check passes, the bridge mints `amount_without_fee` tokens on NEAR for the user, and `locked_tokens[Sol]` drops to 0.

**Net result:** The bridge has minted `2 × amount_without_fee` NEAR-side tokens (once for the relayer, once for the user) while the Ethereum side

### Citations

**File:** near/omni-bridge/src/lib.rs (L932-938)
```rust
        self.burn_tokens_if_needed(fast_transfer.token_id.clone(), amount_without_fee.into());

        self.lock_tokens_if_needed(
            fast_transfer.get_destination_chain(),
            &fast_transfer.token_id,
            amount_without_fee,
        );
```

**File:** near/omni-bridge/src/lib.rs (L1881-1885)
```rust
        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
```

**File:** near/omni-bridge/src/lib.rs (L1997-2040)
```rust
        self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        );
        self.lock_tokens_if_needed(
            transfer_message.get_destination_chain(),
            &token,
            transfer_message.fee.fee.into(),
        );

        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let recipient = if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            require!(
                !status.finalised,
                BridgeError::FastTransferAlreadyFinalised.as_ref()
            );
            Some(status.relayer)
        } else {
            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token,
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            );

            None
        };

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

**File:** near/omni-bridge/src/lib.rs (L2684-2684)
```rust
        self.unlock_tokens_if_needed(transfer_message.get_destination_chain(), &token, token_fee);
```

**File:** near/omni-bridge/src/token_lock.rs (L71-94)
```rust
    fn unlock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(available) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        require!(
            available >= amount,
            TokenLockError::InsufficientLockedTokens.as_ref()
        );

        let remaining = available - amount;
        self.locked_tokens.insert(&key, &remaining);

        LockAction::Unlocked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
    }
```
