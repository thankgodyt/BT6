The code at the cited lines exactly matches the report's claims. Let me confirm the key facts:

- [1](#0-0)  — The TODO comment `// TODO: check how to deal with failed send_tokens` is present at the exact call site.
- [2](#0-1)  — `remove_fast_transfer` (line 2530) and `mark_fast_transfer_as_finalised` (line 2533) execute before the repayment is dispatched.
- [3](#0-2)  — `send_tokens(...).detach()` is confirmed: fire-and-forget, no callback, no rollback.
- [4](#0-3)  — The connector check only validates the caller is the BTC connector; it does not protect against the relayer repayment failing.

All cited code is real and the described behavior is accurate.

---

Audit Report

## Title
Relayer Permanently Loses Fronted BTC Tokens When `send_tokens` Fails in `utxo_fin_transfer_fast` — (File: near/omni-bridge/src/lib.rs)

## Summary
In `utxo_fin_transfer_fast`, the fast-transfer record is irrevocably removed or marked finalised before the relayer repayment is dispatched, and that repayment is fired with `.detach()` — no callback, no rollback. If the underlying `ft_transfer` fails (e.g., relayer account not registered for the BTC NEP-141 token), the failure is silently swallowed, the fast-transfer record is already gone, and the relayer's fronted BTC tokens are permanently unrecoverable. The developers themselves flagged this exact gap with a `// TODO: check how to deal with failed send_tokens` comment at the call site.

## Finding Description
`utxo_fin_transfer` is the callback entry point triggered when the BTC connector calls `ft_transfer_call` with a UTXO proof. When a matching fast-transfer record exists, it delegates to `utxo_fin_transfer_fast` (line 2485). Inside that function, state is mutated first: for NEAR-destination transfers, `remove_fast_transfer` is called at line 2530, permanently deleting the record; for other-chain transfers, `mark_fast_transfer_as_finalised` is called at line 2533, permanently sealing it. Immediately after, the relayer repayment is dispatched at lines 2542–2548 with `.detach()`. NEAR's `.detach()` means no callback is registered on the promise; if `send_tokens` panics or the underlying `ft_transfer` is rejected by the token contract (e.g., relayer account has no storage deposit for the BTC NEP-141 token), the failure is silently discarded. The fast-transfer record is already gone, so there is no retry path, no rollback, and no event that would allow off-chain recovery. The connector authenticity check at lines 2471–2474 only ensures the BTC connector is the caller; it provides no protection against the relayer repayment failing after state mutation.

## Impact Explanation
A relayer who fronted BTC tokens for a fast transfer is entitled to repayment when the UTXO proof is finalised. If the repayment `ft_transfer` fails after the fast-transfer record has been removed or finalised, the relayer's fronted bridged BTC tokens are permanently lost with no recovery path. This is a concrete, permanent loss of bridged funds, matching the allowed critical impact: "loss … of bridged funds across … Bitcoin … flows."

## Likelihood Explanation
The most realistic trigger is a relayer account that lacks a storage deposit for the BTC NEP-141 token at the time the UTXO proof is finalised. This can occur naturally if the relayer's storage registration lapses between the time they front the transfer and the time the proof arrives. It can also be induced by any participant who acts as a relayer using an account not registered for the token. No privileged access is required; any account that participates in the fast-transfer relayer flow can reach this code path through the public `ft_transfer_call` → `utxo_fin_transfer` → `utxo_fin_transfer_fast` chain.

## Recommendation
Replace the `.detach()` pattern with a proper callback:
1. Do **not** call `remove_fast_transfer` / `mark_fast_transfer_as_finalised` before the token transfer succeeds.
2. Register a `#[private]` callback on the `send_tokens` promise.
3. In the callback, only remove/finalise the fast-transfer record on success; on failure, leave the record intact so the relayer can be repaid via a retry or alternative path.

## Proof of Concept
1. Register a fast transfer for a UTXO ID where the relayer account (`relayer.near`) has no storage deposit for the BTC NEP-141 token.
2. Have the BTC connector call `ft_transfer_call` with the matching UTXO proof, triggering `utxo_fin_transfer` → `utxo_fin_transfer_fast`.
3. Observe that `remove_fast_transfer` (line 2530) executes and the record is deleted.
4. Observe that `send_tokens(...).detach()` (lines 2542–2548) fires but the underlying `ft_transfer` to `relayer.near` fails silently because the account is not registered.
5. Assert: the fast-transfer record no longer exists; the relayer's BTC token balance is unchanged. The relayer has permanently lost their fronted tokens with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L2471-2474)
```rust
        require!(
            sender_id == &config.connector,
            BridgeError::SenderIsNotConnector.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L2483-2485)
```rust
        if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            // TODO: check how to deal with failed send_tokens
            return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
```

**File:** near/omni-bridge/src/lib.rs (L2529-2540)
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
```

**File:** near/omni-bridge/src/lib.rs (L2542-2548)
```rust
        self.send_tokens(
            fast_transfer.token_id.clone(),
            fast_transfer_status.relayer,
            amount,
            "",
        )
        .detach();
```
