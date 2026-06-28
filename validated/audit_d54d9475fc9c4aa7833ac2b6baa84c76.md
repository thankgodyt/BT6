### Title
Unchecked Token Transfer Result in Fast Transfer Relayer Repayment Causes Permanent Loss of Relayer Funds - (File: near/omni-bridge/src/lib.rs)

### Summary
In `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast`, the `send_tokens` call that repays the fast-transfer relayer is fired with `.detach()` — no callback checks whether the transfer succeeded. The fast transfer is then permanently marked as finalised in the same transaction. If the underlying `ft_transfer` fails (e.g., the relayer's account is no longer registered for the token), the relayer permanently loses the tokens they fronted on the destination chain, with no recovery path.

### Finding Description

**Location 1 — `process_fin_transfer_to_other_chain`** (`near/omni-bridge/src/lib.rs`, lines 2028–2040):

```rust
if let Some(relayer) = recipient {
    self.send_tokens(token, relayer, amount, "").detach();   // ← no callback
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // ← committed regardless
}
```

`send_tokens` with an empty `msg` and a non-deployed token resolves to `ft_transfer` (line 2103–2106). If `ft_transfer` panics (e.g., recipient lacks storage registration), the detached promise fails silently. The fast transfer is already marked finalised in the same transaction, so it can never be replayed. The relayer's fronted tokens on the destination chain are permanently unrecoverable.

**Location 2 — `utxo_fin_transfer_fast`** (`near/omni-bridge/src/lib.rs`, lines 2529–2548):

```rust
let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
    self.remove_fast_transfer(&fast_transfer.id());   // ← entry deleted
    fast_transfer.amount
} else {
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // ← entry finalised
    ...
};
self.send_tokens(fast_transfer.token_id.clone(), fast_transfer_status.relayer, amount, "")
    .detach();  // ← no callback
```

Same pattern: the fast transfer record is removed or finalised before the token transfer result is known.

**Contrast with the safe path**: `fast_fin_transfer_to_near_callback` (lines 877–892) correctly chains `send_tokens` with a `resolve_fast_transfer` callback that handles failure by removing the fast transfer entry and returning the amount as a refund. The two detached call sites lack this protection.

The project's own security checklist (`near/CLAUDE.md`, line 228) explicitly flags this: *"Check .detach() usage: Detached promises should only be used for non-critical operations."* Repaying a relayer for fronted bridge funds is not a non-critical operation.

### Impact Explanation
A relayer who fronted real tokens on the destination chain (ETH, Solana, etc.) and whose NEAR-side repayment `ft_transfer` fails will permanently lose those tokens. The `finalised_transfers` set already contains the transfer ID (added by `add_fin_transfer` at line 1985), so the transfer cannot be re-submitted. The fast transfer entry is also finalised/removed, closing every recovery path. This constitutes a direct, permanent loss of bridged funds.

### Likelihood Explanation
`ft_transfer` on a NEP-141 token panics when the recipient account is not registered for that token. A relayer who fronted tokens on the destination chain may not hold a storage registration for the corresponding NEAR-side token (e.g., a relayer operating primarily on EVM who sent NEAR-side tokens to the bridge via `ft_transfer_call` but later called `storage_unregister` on the token contract, or whose registration expired). The window between fast-transfer submission and proof finalization can be hours to days, making this a realistic race condition. No privileged access is required to trigger the failure — the relayer's own account state is sufficient.

### Recommendation
Replace the detached calls with a chained callback that reverts the fast-transfer state on failure, mirroring the pattern already used in `fast_fin_transfer_to_near_callback`:

```rust
self.send_tokens(token, relayer, amount, "")
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(RESOLVE_FAST_TRANSFER_GAS)
            .resolve_fast_transfer_repayment(&fast_transfer.id(), relayer, amount),
    );
// move mark_fast_transfer_as_finalised into the callback's success branch
```

The callback should mark the fast transfer as finalised only on success, and on failure should leave the fast transfer entry intact so the repayment can be retried (after the relayer re-registers storage).

### Proof of Concept

1. Relayer R performs a fast transfer for a user's ETH→ETH bridge transfer: R calls `ft_transfer_call` on the NEAR-side USDC contract, sending tokens to the bridge with a `FastFinTransfer` message. Bridge records `FastTransferStatus { relayer: R, finalised: false }`.
2. Between fast-transfer submission and proof arrival, R calls `storage_unregister` on the NEAR-side USDC contract (e.g., to reclaim storage deposit), removing R's USDC account.
3. The original ETH proof arrives at NEAR. A relayer calls `fin_transfer_callback`. Since the recipient is on ETH (not NEAR), `process_fin_transfer_to_other_chain` is invoked.
4. The bridge detects the fast transfer entry for R, calls `send_tokens(usdc, R, amount, "").detach()`. Internally this resolves to `ext_token::ext(usdc).ft_transfer(R, amount, None)`.
5. `ft_transfer` panics: R is not registered for USDC. The detached promise fails silently.
6. In the same transaction, `mark_fast_transfer_as_finalised` commits. The `finalised_transfers` set already contains the transfer ID.
7. R has no mechanism to recover: the fast transfer is finalised, the transfer is finalised, and R's fronted ETH-side tokens are permanently lost. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L877-892)
```rust
        self.send_tokens(
            fast_transfer.token_id.clone(),
            recipient,
            amount_without_fee,
            &fast_transfer.msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(RESOLVE_FAST_TRANSFER_GAS)
                .resolve_fast_transfer(
                    &fast_transfer.token_id,
                    &fast_transfer.id(),
                    amount_without_fee,
                    !fast_transfer.msg.is_empty(),
                ),
        )
```

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

**File:** near/CLAUDE.md (L228-228)
```markdown
4. **Check .detach() usage**: Detached promises should only be used for non-critical operations
```
