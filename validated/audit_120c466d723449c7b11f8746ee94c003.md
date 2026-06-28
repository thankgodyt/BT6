The code evidence is conclusive. Here is the analysis:

---

### Title
Detached `send_tokens` in `utxo_fin_transfer_fast` causes permanent loss of relayer's fronted BTC tokens — (`near/omni-bridge/src/lib.rs`)

### Summary

`utxo_fin_transfer_fast` removes or marks the fast-transfer record as finalised **before** attempting to repay the relayer, and the repayment call is `.detach()`ed (fire-and-forget). If the token transfer to the relayer fails for any reason (e.g., relayer account not registered for the BTC token), the fast-transfer record is gone with no rollback path, and the relayer's fronted tokens are permanently lost.

### Finding Description

In `utxo_fin_transfer_fast` (lib.rs:2518–2561):

1. **State mutation happens first** — for NEAR-destination transfers, `remove_fast_transfer` is called at line 2530; for other-chain destinations, `mark_fast_transfer_as_finalised` is called at line 2533. Both are unconditional and happen before any repayment attempt. [1](#0-0) 

2. **Repayment is fire-and-forget** — `send_tokens` is called at lines 2542–2548 and immediately `.detach()`ed. Its result (success or failure) is never observed, and there is no callback to restore state on failure. [2](#0-1) 

3. **The developer already acknowledged this** — the call site in `utxo_fin_transfer` at line 2484 contains an explicit `// TODO: check how to deal with failed send_tokens` comment, confirming the unresolved risk. [3](#0-2) 

4. **Entry point is gated but reachable** — `utxo_fin_transfer` enforces `sender_id == &config.connector` (lines 2471–2474), so only the registered BTC connector can trigger this path via `ft_transfer_call`. This is a normal production path, not an admin-only one. [4](#0-3) 

### Impact Explanation

When `send_tokens` fails (e.g., relayer not storage-registered for the BTC token), the fast-transfer record has already been deleted/finalised. There is no mechanism to re-attempt repayment or restore the record. The relayer permanently loses the tokens they fronted for the fast transfer. This matches the Critical scope: **permanent loss of bridged funds**.

### Likelihood Explanation

NEP-141 tokens require storage registration. A relayer account that is not registered for the specific BTC token will cause `ft_transfer` to panic inside `send_tokens`. This is a realistic operational condition, not a contrived one. The TODO comment confirms the developers are aware the failure case is unhandled.

### Recommendation

- Move `remove_fast_transfer` / `mark_fast_transfer_as_finalised` into a **callback** that only executes after `send_tokens` resolves successfully.
- Alternatively, keep the state mutation but add a recovery callback: on failure, restore the fast-transfer record so the relayer can be repaid in a subsequent call.
- Ensure the relayer's storage registration for the token is verified (or a storage deposit is forced) before the fast-transfer record is mutated.

### Proof of Concept

1. Register a fast transfer for a UTXO ID where the relayer account (`relayer.near`) is **not** storage-registered for the BTC token.
2. Have the BTC connector call `ft_transfer_call` with the matching UTXO data, triggering `utxo_fin_transfer` → `utxo_fin_transfer_fast`.
3. Observe: `remove_fast_transfer` executes at line 2530 (fast-transfer record deleted).
4. Observe: `send_tokens(...).detach()` at lines 2542–2548 fires but the inner `ft_transfer` panics because `relayer.near` has no storage deposit.
5. Assert: fast-transfer record is gone; `relayer.near` token balance is unchanged. The relayer's fronted tokens are unrecoverable.

### Citations

**File:** near/omni-bridge/src/lib.rs (L2471-2474)
```rust
        require!(
            sender_id == &config.connector,
            BridgeError::SenderIsNotConnector.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L2483-2486)
```rust
        if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            // TODO: check how to deal with failed send_tokens
            return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
        }
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
