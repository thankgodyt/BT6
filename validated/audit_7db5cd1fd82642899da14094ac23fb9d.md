### Title
TOCTOU Race Between `fast_fin_transfer` and `fin_transfer` Enables Double-Spend of Bridged Tokens — (`near/omni-bridge/src/lib.rs`)

### Summary

`fast_fin_transfer` (NEAR-recipient path) checks `finalised_transfers` at entry but defers the actual token send to an async callback (`fast_fin_transfer_to_near_callback`). That callback never re-checks `finalised_transfers`. If `fin_transfer` completes and writes to `finalised_transfers` during the async gap, both flows independently send tokens to the recipient, producing a double-spend.

### Finding Description

**Entry point — `fast_fin_transfer` (line 778):**

The only guard against a transfer that has already been finalized is the `is_unified_transfer_finalised` check, which reads `finalised_transfers`: [1](#0-0) 

For a NEAR recipient, the function does **not** write anything to `fast_transfers` or `finalised_transfers` at this point. It only schedules an async cross-contract call: [2](#0-1) 

**Callback — `fast_fin_transfer_to_near_callback` (line 838):**

When the callback fires, it calls `add_fast_transfer` (which checks `fast_transfers`, not `finalised_transfers`) and then unconditionally sends tokens: [3](#0-2) [4](#0-3) 

There is no re-check of `is_unified_transfer_finalised` anywhere in the callback.

**Concurrent `fin_transfer` path — `process_fin_transfer_to_near` (line 1868):**

`fin_transfer_callback` calls `add_fin_transfer` (writes to `finalised_transfers`) and then reads `fast_transfers` to decide the recipient: [5](#0-4) 

If `fast_transfers` does not yet contain the entry (because `fast_fin_transfer_to_near_callback` has not run yet), `process_fin_transfer_to_near` falls into the `None` branch and sends tokens to the original recipient: [6](#0-5) 

**Race window:**

```
Block N   : fast_fin_transfer tx submitted
            → is_unified_transfer_finalised check passes (finalised_transfers empty)
            → schedules check_or_pay_ft_storage → fast_fin_transfer_to_near_callback

Block N+1 : fin_transfer tx submitted
            → verify_proof (async)

Block N+2 : fin_transfer_callback runs
            → add_fin_transfer writes X to finalised_transfers
            → get_fast_transfer_status returns None  ← fast_transfers still empty
            → send_tokens to recipient  ← FIRST payment

Block N+2 : fast_fin_transfer_to_near_callback runs
            → add_fast_transfer writes X to fast_transfers (no finalised_transfers check)
            → send_tokens to recipient  ← SECOND payment (double-spend)
```

`add_fast_transfer` only guards against a duplicate fast transfer (two `fast_fin_transfer` calls), not against a fast transfer that races with a completed `fin_transfer`: [7](#0-6) 

### Impact Explanation

The recipient receives `amount_without_fee` tokens twice for a single cross-chain transfer. If the attacker controls both the recipient account and the relayer account (or colludes with a relayer), they net `amount_without_fee` tokens for free. The bridge's token supply is inflated by exactly that amount, constituting a direct theft of bridged funds.

### Likelihood Explanation

Relayer registration is permissionless via `apply_for_trusted_relayer` with a NEAR stake deposit and a waiting period: [8](#0-7) 

Any user can become a trusted relayer, submit both `fast_fin_transfer` and `fin_transfer` for their own cross-chain transfer, and time the submissions so that `fin_transfer_callback` executes during the async gap of `fast_fin_transfer`. The gap spans at least one full block (the `check_or_pay_ft_storage` cross-contract call), which is sufficient for a concurrently submitted `fin_transfer` (whose proof verification was submitted earlier) to complete. This is a deterministic, repeatable exploit requiring no external coordination beyond controlling a relayer account.

### Recommendation

Re-check `is_unified_transfer_finalised` at the top of `fast_fin_transfer_to_near_callback`, before calling `add_fast_transfer` or sending any tokens. If the transfer has already been finalized, panic and allow the NEP-141 `ft_transfer_call` to refund the relayer's tokens:

```rust
// At the start of fast_fin_transfer_to_near_callback:
if self.is_unified_transfer_finalised(&fast_transfer.transfer_id) {
    env::panic_str(BridgeError::TransferAlreadyFinalised.to_string().as_str());
}
```

This mirrors the guard already present in `fast_fin_transfer` itself and closes the TOCTOU window.

### Proof of Concept

1. Attacker stakes NEAR and waits for `apply_for_trusted_relayer` activation.
2. Attacker initiates a transfer of 1000 USDC from Ethereum to their NEAR account.
3. Attacker submits `fast_fin_transfer` via `ft_transfer_call` (fronting 999 USDC, fee = 1 USDC). The call schedules `check_or_pay_ft_storage → fast_fin_transfer_to_near_callback` but does not yet write to `fast_transfers`.
4. In the same or next block, attacker submits `fin_transfer` with the valid Ethereum proof. `verify_proof` is async; the callback `fin_transfer_callback` fires one block later.
5. `fin_transfer_callback` → `process_fin_transfer_to_near`: `add_fin_transfer` writes the transfer ID to `finalised_transfers`; `get_fast_transfer_status` returns `None` (step 3's callback has not run yet); `send_tokens` sends 999 USDC to attacker's NEAR account. **First payment.**
6. `fast_fin_transfer_to_near_callback` fires: `add_fast_transfer` succeeds (no entry in `fast_transfers`); `send_tokens` sends 999 USDC to attacker's NEAR account. **Second payment.**
7. Attacker receives 1998 USDC total. Net gain: 999 USDC (the fronted amount is returned as the second payment, and the first payment is pure profit).

### Citations

**File:** near/omni-bridge/src/lib.rs (L778-780)
```rust
        if self.is_unified_transfer_finalised(&fast_fin_transfer_msg.transfer_id) {
            env::panic_str(BridgeError::TransferAlreadyFinalised.to_string().as_str());
        }
```

**File:** near/omni-bridge/src/lib.rs (L812-827)
```rust
            Self::check_or_pay_ft_storage(
                &deposit_action,
                &mut NearToken::from_yoctonear(storage_deposit_amount),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(
                        FAST_TRANSFER_CALLBACK_GAS.saturating_add(FT_TRANSFER_CALL_GAS),
                    )
                    .fast_fin_transfer_to_near_callback(
                        &fast_transfer,
                        signer_id,
                        fast_fin_transfer_msg.relayer,
                    ),
            )
            .into()
```

**File:** near/omni-bridge/src/lib.rs (L854-856)
```rust
        let required_balance = self
            .add_fast_transfer(fast_transfer, relayer_id, storage_payer.clone())
            .saturating_add(ONE_YOCTO);
```

**File:** near/omni-bridge/src/lib.rs (L877-882)
```rust
        self.send_tokens(
            fast_transfer.token_id.clone(),
            recipient,
            amount_without_fee,
            &fast_transfer.msg,
        )
```

**File:** near/omni-bridge/src/lib.rs (L1875-1879)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());
```

**File:** near/omni-bridge/src/lib.rs (L1897-1901)
```rust
            None => (
                recipient,
                transfer_message.msg.clone(),
                predecessor_account_id.clone(),
            ),
```

**File:** near/omni-bridge/src/lib.rs (L2253-2265)
```rust
        require!(
            self.fast_transfers
                .insert(
                    &fast_transfer.id(),
                    &FastTransferStatusStorage::V0(FastTransferStatus {
                        relayer,
                        storage_owner,
                        finalised: false,
                    }),
                )
                .is_none(),
            BridgeError::FastTransferAlreadyPerformed.as_ref()
        );
```

**File:** near/omni-tests/src/relayer_staking.rs (L103-109)
```rust
        let result = applicant
            .call(env.bridge_contract.id(), "apply_for_trusted_relayer")
            .deposit(NearToken::from_near(1000))
            .max_gas()
            .transact()
            .await?;
        result.into_result()?;
```
