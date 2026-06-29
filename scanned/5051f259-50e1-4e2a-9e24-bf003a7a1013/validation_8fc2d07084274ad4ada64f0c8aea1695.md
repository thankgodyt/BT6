### Title
`locked_tokens` Escrow Mis-Accounting When `send_tokens` Fails Silently in Fast-Transfer Finalization — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

In `process_fin_transfer_to_other_chain`, when a prior fast transfer exists, the bridge irrevocably updates its `locked_tokens` escrow ledger and permanently marks the fast transfer as finalised **before** confirming that the token reimbursement to the relayer actually succeeded. The `send_tokens` call is fired with `.detach()`, meaning any failure is silently swallowed. This is the direct NEAR analog of the Gearbox `_transferAssetsTo()` bug: a running accounting total is mutated regardless of whether the underlying transfer succeeded.

---

### Finding Description

`process_fin_transfer_to_other_chain` is invoked from `fin_transfer_callback` whenever a verified inbound proof targets a non-NEAR destination chain. The function performs three irreversible state mutations before dispatching the token transfer, and then dispatches the transfer with no success callback:

```
// near/omni-bridge/src/lib.rs  lines 1997-2040

self.unlock_tokens_if_needed(          // (1) decrements locked_tokens[origin][token]
    transfer_message.get_origin_chain(),
    &token,
    transfer_message.amount.0,
);
self.lock_tokens_if_needed(            // (2) increments locked_tokens[destination][token] by fee
    transfer_message.get_destination_chain(),
    &token,
    transfer_message.fee.fee.into(),
);

// fast-transfer branch
if let Some(relayer) = recipient {
    self.send_tokens(                  // (3) cross-contract call — result IGNORED
        token,
        relayer,
        U128(transfer_message.amount_without_fee()...),
        "",
    )
    .detach();                         // ← no callback, failure is silent
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // (4) permanent
}
``` [1](#0-0) 

`send_tokens` for a non-deployed (locked) token issues an NEP-141 `ft_transfer` cross-contract call:

```rust
ext_token::ext(token)
    .with_attached_deposit(ONE_YOCTO)
    .with_static_gas(FT_TRANSFER_GAS)
    .ft_transfer(recipient, amount, None)
``` [2](#0-1) 

`ft_transfer` panics (and thus the promise fails) if the recipient has no storage registered on the token contract, or if the token contract enforces a blacklist (USDC, USDT). Because the call is `.detach()`-ed, the failure is never observed by the bridge.

The `locked_tokens` map is the bridge's canonical escrow ledger: [3](#0-2) 

`unlock_tokens` enforces `available >= amount` and panics otherwise: [4](#0-3) 

There is no `revert_lock_actions` call in the fast-transfer branch of `process_fin_transfer_to_other_chain`, unlike the `fin_transfer_send_tokens_callback` path which correctly reverts on failure: [5](#0-4) 

---

### Impact Explanation

When `send_tokens` fails silently:

1. **`locked_tokens[origin][token]`** is permanently decremented by `amount` even though the relayer never received the tokens. The bridge's escrow record now claims fewer tokens are locked on the origin chain than actually are, corrupting the invariant that `locked_tokens` equals the bridge's real on-chain holdings.

2. **`locked_tokens[destination][token]`** is permanently incremented by `fee` even though no fee was actually locked. This inflates the destination-chain escrow counter.

3. **The fast transfer is permanently marked as finalised** (`mark_fast_transfer_as_finalised`), so the relayer can never retry the reimbursement.

4. **The relayer loses their pre-funded tokens.** They transferred their own tokens to the recipient during the fast transfer and are entitled to reimbursement during finalization. With the transfer silently failing and the state permanently committed, those tokens are unrecoverable.

The corrupted `locked_tokens` ledger propagates to all future bridge operations: subsequent `fin_transfer` calls from the origin chain will hit `ERR_INSUFFICIENT_LOCKED_TOKENS` for amounts that should be valid, and the inflated destination counter misrepresents the bridge's solvency on that chain.

---

### Likelihood Explanation

The bridge is explicitly designed to support USDC and USDT as collateral tokens (both implement ERC-20/NEP-141 blacklists). If a relayer's NEAR account is blacklisted by the token issuer between the time they execute a fast transfer and the time `fin_transfer` is called, `ft_transfer` will panic and the promise will fail. Because the call is detached, the bridge never detects this. The same failure occurs if the relayer's account lacks storage registration on the specific token contract at finalization time. Both conditions are reachable without any admin compromise.

---

### Recommendation

Replace the fire-and-forget `.detach()` pattern with a callback that reverts the `locked_tokens` mutations and un-finalises the fast transfer if `send_tokens` fails, mirroring the existing `fin_transfer_send_tokens_callback` / `revert_lock_actions` pattern already used in the NEAR-recipient path: [6](#0-5) 

Concretely: record the `LockAction`s produced by `unlock_tokens_if_needed` and `lock_tokens_if_needed`, pass them to a new `resolve_fin_transfer_to_other_chain_callback`, and call `revert_lock_actions` plus un-mark the fast transfer if the promise result is `Failed`.

---

### Proof of Concept

1. Token is a non-deployed NEP-141 (e.g., USDC) with a blacklist. `locked_tokens[(Eth, usdc)]` = 1 000 000.
2. Relayer calls `ft_transfer_call` → `fast_fin_transfer` → `fast_fin_transfer_to_near_callback` → sends 999 000 USDC to recipient. Fast transfer recorded with `relayer = relayer.near`.
3. Circle blacklists `relayer.near` on the USDC contract.
4. Any trusted relayer submits the EVM receipt to `fin_transfer`. `fin_transfer_callback` routes to `process_fin_transfer_to_other_chain`.
5. `unlock_tokens_if_needed(Eth, usdc, 1_000_000)` → `locked_tokens[(Eth, usdc)]` = 0. ✓ committed.
6. `lock_tokens_if_needed(destination, usdc, fee)` → `locked_tokens[(dest, usdc)]` += fee. ✓ committed.
7. `send_tokens(usdc, relayer.near, 999_000, "").detach()` → USDC `ft_transfer` panics (blacklisted). Promise fails. **Bridge never sees the failure.**
8. `mark_fast_transfer_as_finalised(...)` → fast transfer permanently finalised.
9. Result: `locked_tokens[(Eth, usdc)]` = 0 (should be 1 000 000 still held by bridge), relayer lost 999 000 USDC, fast transfer cannot be retried. [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L242-242)
```rust
    pub locked_tokens: LookupMap<(ChainKind, AccountId), u128>,
```

**File:** near/omni-bridge/src/lib.rs (L1702-1718)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L2102-2107)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        } else {
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
