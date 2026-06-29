### Title
Fire-and-Forget Token Transfer to Relayer Causes Permanent Fund Loss After Fast Transfer Finalisation — (`near/omni-bridge/src/lib.rs`)

### Summary

In `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast`, the bridge marks a fast transfer as finalised **before** confirming that the reimbursement token transfer to the relayer succeeded. The token transfer is dispatched with `.detach()` (fire-and-forget), so any failure is silently ignored. The fast transfer state is permanently updated regardless, making the relayer's reimbursement irrecoverable.

### Finding Description

The external report's vulnerability class is: **state is cleared/consumed before confirming a dependent operation succeeds, causing permanent loss of funds**. The analog in NEAR Omni Bridge is the fire-and-forget pattern used when reimbursing a fast-transfer relayer during canonical finalisation.

**Root cause in `process_fin_transfer_to_other_chain`:** [1](#0-0) 

```rust
if let Some(relayer) = recipient {
    self.send_tokens(token, relayer, U128(...), "")
        .detach();                                    // ← fire-and-forget
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // ← state updated unconditionally
}
```

`send_tokens` is called with `.detach()`, meaning its result (success or failure) is never inspected. Immediately after, `mark_fast_transfer_as_finalised` permanently records the fast transfer as done. [2](#0-1) 

Once `finalised = true` is written, no code path allows re-sending the reimbursement. The same pattern appears in `utxo_fin_transfer_fast`: [3](#0-2) 

```rust
let amount = if ... == ChainKind::Near {
    self.remove_fast_transfer(&fast_transfer.id());   // ← state cleared
    ...
} else {
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // ← state cleared
    ...
};
self.send_tokens(..., fast_transfer_status.relayer, amount, "").detach(); // ← fire-and-forget
```

In both cases the fast-transfer record is consumed/finalised **before** the token transfer is confirmed.

### Impact Explanation

If `send_tokens` fails (e.g., the relayer's account lacks NEP-141 storage registration for the token, the token contract panics, or gas is exhausted in the detached receipt):

1. The relayer who pre-paid tokens to the recipient receives **no reimbursement**.
2. The fast transfer is permanently marked finalised — no retry path exists.
3. The reimbursement tokens remain locked inside the bridge contract with no mechanism to recover them.

This constitutes **permanent freezing of bridged funds** belonging to the relayer.

### Likelihood Explanation

The `send_tokens` call for a non-deployed token uses `ft_transfer`, which requires the recipient to have storage registered on the token contract. A relayer whose storage registration has lapsed or was never set up for a particular token will silently lose their reimbursement. For deployed tokens, `mint` is called — any panic in the token contract has the same effect. The scenario is reachable through normal bridge operation without any privileged compromise.

### Recommendation

Replace the `.detach()` pattern with a proper callback that reverts the finalisation state if the token transfer fails, mirroring the existing `resolve_fast_transfer` / `fin_transfer_send_tokens_callback` pattern used elsewhere in the contract: [4](#0-3) 

Specifically, `mark_fast_transfer_as_finalised` (or `remove_fast_transfer`) should only be called inside a callback that verifies the token transfer succeeded. If it failed, the finalised flag must be rolled back so the reimbursement can be retried.

### Proof of Concept

1. Trusted relayer R performs a fast transfer for transfer ID `T` (pre-pays tokens to recipient on NEAR).
2. Canonical `fin_transfer` is called for `T` with a non-NEAR destination, triggering `process_fin_transfer_to_other_chain`.
3. The bridge detects the fast transfer record for `T` and calls `send_tokens(token, R, amount, "").detach()` followed immediately by `mark_fast_transfer_as_finalised(&fast_transfer.id())`.
4. The `ft_transfer` to R fails (e.g., R has no storage for `token`).
5. Because the promise was detached, the failure is invisible to the bridge. The fast transfer is already finalised.
6. R has lost `amount` tokens. The tokens remain in the bridge contract. No recovery path exists.

### Citations

**File:** near/omni-bridge/src/lib.rs (L895-912)
```rust
    #[private]
    pub fn resolve_fast_transfer(
        &mut self,
        token_id: &AccountId,
        fast_transfer_id: &FastTransferId,
        amount: U128,
        is_ft_transfer_call: bool,
    ) -> U128 {
        // Burn the tokens to ensure the locked tokens are not double-minted
        self.burn_tokens_if_needed(token_id.clone(), amount);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L2027-2041)
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
        } else {
```

**File:** near/omni-bridge/src/lib.rs (L2270-2277)
```rust
    fn mark_fast_transfer_as_finalised(&mut self, fast_transfer_id: &FastTransferId) {
        let mut status = self
            .get_fast_transfer_status(fast_transfer_id)
            .near_expect(BridgeError::FastTransferNotFound);
        status.finalised = true;
        self.fast_transfers
            .insert(fast_transfer_id, &FastTransferStatusStorage::V0(status));
    }
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
