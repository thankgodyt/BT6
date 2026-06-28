### Title
Detached `send_tokens` Promise on Fast-Transfer Relayer Repayment Causes Permanent Loss of Relayer Funds — (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

In two places within the NEAR bridge contract, when a fast-transfer relayer is owed repayment, `send_tokens()` is called with `.detach()` — a fire-and-forget pattern that discards the promise result. If the token transfer fails (e.g., the relayer's account lacks NEP-141 storage registration for a native/non-deployed token), the fast-transfer record is simultaneously marked as finalised or removed in the same transaction. There is no callback to detect the failure and restore state. The relayer's fronted tokens are permanently lost with no recovery path.

The developers themselves flagged one of these sites with `// TODO: check how to deal with failed send_tokens` at line 2484.

---

### Finding Description

**Root cause location 1 — `process_fin_transfer_to_other_chain`**

When a proof-based `fin_transfer` is processed and the destination is a non-NEAR chain, the bridge checks whether a relayer previously fronted tokens via `fast_fin_transfer`. If so, it must repay the relayer:

```rust
// near/omni-bridge/src/lib.rs:2028-2040
if let Some(relayer) = recipient {
    self.send_tokens(
        token,
        relayer,
        U128(transfer_message.amount_without_fee()...),
        "",
    )
    .detach();                                          // ← fire-and-forget
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // ← state committed
}
```

`send_tokens` is detached before `mark_fast_transfer_as_finalised` is called. Both operations execute in the same NEAR transaction frame: the state mutation is committed regardless of whether the detached promise succeeds or fails. If the `ft_transfer` (for native tokens) or `mint` (for deployed tokens) reverts, the fast-transfer entry is already finalised and cannot be retried. The relayer's fronted tokens are gone.

**Root cause location 2 — `utxo_fin_transfer_fast`**

When the UTXO connector finalises a transfer that was previously fast-transferred, the same pattern appears:

```rust
// near/omni-bridge/src/lib.rs:2529-2548
let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
    self.remove_fast_transfer(&fast_transfer.id());   // ← record deleted
    fast_transfer.amount
} else {
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // ← record finalised
    U128(fast_transfer.amount_without_fee()...)
};

self.send_tokens(
    fast_transfer.token_id.clone(),
    fast_transfer_status.relayer,
    amount,
    "",
)
.detach();                                            // ← fire-and-forget
```

The fast-transfer record is removed or finalised before the detached promise is scheduled. A failed token transfer leaves the relayer with no recourse. The developer comment at line 2484 explicitly acknowledges this is unresolved:

```rust
// TODO: check how to deal with failed send_tokens
return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
```

**Why `send_tokens` can fail for a non-deployed token**

`send_tokens` branches on token type. For native (non-deployed) tokens it calls `ft_transfer`, which requires the recipient to have a registered NEP-141 storage balance on the token contract. If the relayer's account is not registered, the call panics and the promise fails — silently, because it is detached.

```rust
// near/omni-bridge/src/lib.rs:2102-2106
} else if msg.is_empty() {
    ext_token::ext(token)
        .with_attached_deposit(ONE_YOCTO)
        .with_static_gas(FT_TRANSFER_GAS)
        .ft_transfer(recipient, amount, None)   // panics if recipient not registered
}
```

---

### Impact Explanation

A relayer who fronted tokens for a fast transfer (locking their own capital) receives no repayment if the detached `send_tokens` promise fails. The fast-transfer record is simultaneously finalised, so:

- The relayer cannot retry the claim.
- No admin function exists to recover the stuck tokens.
- The tokens remain locked inside the bridge contract (for native tokens) or are minted to no one (for deployed tokens), constituting a permanent loss of bridged funds.

This matches the **Critical** impact class: permanent freezing / loss of bridged funds.

---

### Likelihood Explanation

The failure condition — a relayer's account lacking NEP-141 storage registration for the repayment token — is realistic:

- A relayer may register storage for the token they front but not for the token they receive back if the bridge maps to a different on-chain token ID.
- Any transient panic in the token contract (e.g., out-of-gas on the token side, contract upgrade mid-flight) also triggers the silent failure.
- The UTXO path (`utxo_fin_transfer_fast`) is reachable whenever the registered UTXO connector submits a finalisation for a previously fast-transferred UTXO, which is a normal operational flow.

The developer TODO comment confirms the team is aware the failure case is unhandled.

---

### Recommendation

Replace the `.detach()` pattern with a proper callback that checks the promise result and, on failure, restores the fast-transfer record (or re-inserts it) so the relayer can retry:

```rust
self.send_tokens(token, relayer, amount, "")
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(RESOLVE_RELAYER_REPAYMENT_GAS)
            .resolve_relayer_repayment(&fast_transfer_id, relayer, amount),
    );
// Only call mark_fast_transfer_as_finalised inside the callback, on success.
```

In `resolve_relayer_repayment`, if the promise failed, re-insert the fast-transfer entry so the repayment can be retried. This mirrors the existing `resolve_fast_transfer` callback pattern already used in `fast_fin_transfer_to_near_callback`.

---

### Proof of Concept

**Scenario (EVM → NEAR fast transfer, repayment path):**

1. Trusted relayer R calls `ft_transfer_call` on token T, routing through `ft_on_transfer` → `fast_fin_transfer` → `fast_fin_transfer_to_other_chain`. A `FastTransfer` entry is stored with `relayer = R`.

2. R's account is registered for token T on the NEAR side, but the bridge's internal token mapping resolves to a *different* NEP-141 contract T′ for which R has no storage balance.

3. A second trusted relayer (or R itself) submits the EVM proof via `fin_transfer`. The call chain reaches `process_fin_transfer_to_other_chain`.

4. At line 2009, `get_fast_transfer_status` returns `Some(status)` with `relayer = R`.

5. At line 2029, `send_tokens(T′, R, amount, "")` is scheduled and immediately `.detach()`-ed.

6. At line 2040, `mark_fast_transfer_as_finalised` commits the finalised state to storage.

7. The detached `ft_transfer` on T′ panics because R has no storage balance on T′. The promise failure is silently discarded.

8. R has lost `amount` tokens. The fast-transfer entry is finalised and cannot be reopened. No admin recovery path exists. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** near/omni-bridge/src/lib.rs (L2028-2040)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L2102-2106)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
```

**File:** near/omni-bridge/src/lib.rs (L2483-2485)
```rust
        if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
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
