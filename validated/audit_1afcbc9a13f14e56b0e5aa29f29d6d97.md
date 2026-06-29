Audit Report

## Title
Native NEAR Fee Permanently Locked in Pending Transfers With No Recovery Mechanism - (File: `near/omni-bridge/src/lib.rs`)

## Summary
When a user initiates a NEAR-side cross-chain transfer with a `native_fee`, the fee is deducted from their tracked `accounts_balances.available` and held in the contract's NEAR balance. If a relayer never finalizes the transfer, the native fee is permanently locked: no cancel function exists, `remove_transfer_message` does not refund the native fee portion, and `update_transfer_fee` deposits additional NEAR into the contract with zero accounting entry, compounding the unrecoverable amount.

## Finding Description

**Step 1 — Fee deducted from user's storage balance at initiation.**

In `init_transfer_internal` (L1834–1836), `required_storage_balance` is computed as the on-chain storage cost for the pending transfer entry *plus* the full `native_fee`:

```rust
let required_storage_balance = self
    .add_transfer_message(transfer_message.clone(), storage_owner.clone())
    .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));
```

`try_update_storage_balance` then subtracts this combined amount from `accounts_balances[storage_owner].available`. The native fee is now held in the contract's NEAR balance; the user's tracked balance no longer includes it.

**Step 2 — `update_transfer_fee` deposits additional NEAR with no accounting update.**

At L411–420, `update_transfer_fee` enforces `attached_deposit == diff_native_fee` but never calls any storage-balance update function:

```rust
let diff_native_fee = fee.native_fee.0
    .checked_sub(current_fee.native_fee.0)
    .near_expect(BridgeError::LowerFee);

require!(
    NearToken::from_yoctonear(diff_native_fee) == env::attached_deposit(),
    BridgeError::InvalidAttachedDeposit.as_ref()
);
```

The extra NEAR lands in the contract's balance with no entry in `accounts_balances`, making it entirely unrecoverable through any storage management path regardless of whether the transfer is ever completed.

**Step 3 — The only release path is relayer completion.**

`send_fee_internal` (L2664–2667) is the sole disbursement point for native fees:

```rust
} else if origin_chain == ChainKind::Near {
    Promise::new(fee_recipient.clone())
        .transfer(NearToken::from_yoctonear(transfer_message.fee.native_fee.0))
        .detach();
```

This is only reachable via `claim_fee_callback`, which requires a relayer to submit a valid finalization proof from the destination chain.

**Step 4 — No cancel or recovery mechanism exists.**

Searches across the contract confirm: no `cancel_transfer`, `storage_unregister`, or `withdraw_native` function exists. `remove_transfer_message` refunds only the storage byte cost of the pending transfer entry, not the `native_fee` amount that was separately deducted from `accounts_balances`. The `update_transfer_fee` additional deposit has no accounting entry at all and is unrecoverable through any code path.

**Exploit flow:**
1. User calls `init_transfer` with `native_fee = X` → X yoctoNEAR deducted from `accounts_balances.available`, held in contract.
2. User calls `update_transfer_fee` increasing fee to Y → `(Y - X)` yoctoNEAR attached as deposit, stored in contract with no accounting entry.
3. No relayer finalizes the transfer (destination chain unsupported, relayer offline, transfer malformed, etc.).
4. User calls `remove_transfer_message` → only storage byte cost refunded; X and `(Y - X)` remain locked forever.

## Impact Explanation

This constitutes **permanent freezing of user funds** (native NEAR) held by the bridge contract, matching the Critical impact class: *"permanent freezing of bridged funds"* and *"fee mis-accounting … that changes user or protocol balances."* The `update_transfer_fee` path creates an additional untracked NEAR balance discrepancy that persists even when transfers are completed, constituting ongoing fee mis-accounting in the contract's balance sheet.

## Likelihood Explanation

Any unprivileged user can trigger this by initiating a transfer to a low-activity destination chain or one experiencing relayer downtime, then calling `update_transfer_fee` one or more times. No attacker capability is required — the victim triggers the loss themselves through normal contract usage. The condition (no relayer completing the transfer) is realistic for new chains, congested networks, or if the relayer set shrinks. The loss scales with the `native_fee` amount and is repeatable across any number of users.

## Recommendation

1. **Add a cancel/reclaim function** (callable only by the transfer owner after a timeout) that calls `remove_transfer_message`, refunds the full `native_fee` from the contract's NEAR balance back to the user, and restores `accounts_balances.available` accordingly.
2. **Track `update_transfer_fee` deposits in `accounts_balances`**: credit the `diff_native_fee` deposit to the storage owner's balance entry so it is subject to the same accounting and recovery logic as the initial fee.
3. **Alternatively**, hold the native fee in a dedicated per-transfer escrow map (keyed by `TransferId`) so it can be precisely refunded on cancellation without relying on implicit contract-balance arithmetic.

## Proof of Concept

```
1. Deploy the omni-bridge contract on localnet.
2. Register account A with sufficient storage balance (e.g., 1 NEAR).
3. Call init_transfer from A with native_fee = 0.5 NEAR to a valid destination.
   → Observe accounts_balances[A].available decreases by storage_cost + 0.5 NEAR.
4. Call update_transfer_fee from A, attaching 0.2 NEAR (new native_fee = 0.7 NEAR).
   → Observe accounts_balances[A].available is unchanged (no credit recorded).
5. Do NOT submit any relayer proof.
6. Call remove_transfer_message for the transfer.
   → Observe accounts_balances[A].available increases only by storage_cost.
   → 0.5 NEAR (from step 3) and 0.2 NEAR (from step 4) remain in contract balance.
7. Attempt storage_withdraw or any other recovery call → no function exists to reclaim the 0.7 NEAR.
```

An invariant/fuzz test can assert: `sum(accounts_balances[*].available) + sum(pending_native_fees) + storage_byte_costs == contract.balance` — this invariant is broken after any `update_transfer_fee` call.