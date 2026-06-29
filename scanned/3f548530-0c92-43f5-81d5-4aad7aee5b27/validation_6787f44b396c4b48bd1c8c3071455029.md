### Title
`ClaimFeeEvent` Emitted Before Token Transfer Completes, With Detached Native-Fee Promise — (`near/omni-bridge/src/lib.rs`)

### Summary

In `send_fee_internal`, the `ClaimFeeEvent` is logged **before** the actual token-fee cross-contract call is dispatched, and the native-fee sub-transfer is fire-and-forgotten via `.detach()`. If either transfer fails, the event has already been committed to the chain, the transfer message has already been removed from storage, and there is no callback to detect or recover from the failure. The relayer permanently loses their fee while off-chain indexers observe a `ClaimFeeEvent` that never corresponded to a real payout.

### Finding Description

`send_fee_internal` is the terminal step of the `claim_fee` flow. Its call chain is:

```
claim_fee (public, trusted-relayer)
  → verify_proof (cross-contract)
    → claim_fee_callback (#[private])
        → remove_transfer_message   ← state permanently changed
        → send_fee_internal
            → native-fee Promise::transfer / mint  .detach()  ← result ignored
            → env::log_str(ClaimFeeEvent)                     ← event committed
            → ft_transfer / mint returned as PromiseOrValue   ← no failure callback
```

Two distinct unchecked-transfer sub-issues exist inside `send_fee_internal`:

**Issue A – Native fee is detached (fire-and-forget)** [1](#0-0) 

`Promise::new(fee_recipient).transfer(...)` and `ext_token::ext(...).mint(...).detach()` both discard their result. If the NEAR transfer fails (e.g., the fee-recipient account does not exist) or the wrapped-token mint fails (e.g., out-of-gas), the native fee is silently lost.

**Issue B – `ClaimFeeEvent` is emitted before the token-fee transfer** [2](#0-1) 

The event is logged synchronously, then the token-fee cross-contract call is returned: [3](#0-2) 

`claim_fee_callback` returns this `PromiseOrValue<()>` directly with no chained callback: [4](#0-3) 

If `ft_transfer` or `mint` fails (e.g., recipient not registered for the token, insufficient gas, token contract panic), the failure receipt is silently dropped. The `ClaimFeeEvent` is already on-chain and the transfer message is already gone.

The same detach-then-log pattern also appears in `utxo_fin_transfer_fast`, where `send_tokens(...).detach()` is called and the fast-transfer state is permanently mutated before the `UtxoTransferEvent` is emitted: [5](#0-4) 

And in `process_fin_transfer_to_other_chain`, where `send_tokens(...).detach()` is followed by `mark_fast_transfer_as_finalised` and then `FinTransferEvent`: [6](#0-5) 

### Impact Explanation

- The relayer's fee (native and/or token) is permanently lost: `remove_transfer_message` has already executed, so there is no stored state to retry from.
- `ClaimFeeEvent` / `UtxoTransferEvent` / `FinTransferEvent` are committed to the chain even though no tokens moved, causing off-chain indexers, relayer dashboards, and downstream bridge consumers to record a successful payout that never occurred.
- In the `utxo_fin_transfer_fast` / `process_fin_transfer_to_other_chain` paths the fast-transfer entry is permanently marked finalised or removed, so the relayer can never recover the funds through any retry path.

This constitutes **loss of bridged/relayer funds** and **escrow mis-accounting** (locked-token counters are updated while the actual transfer silently fails).

### Likelihood Explanation

The failure conditions are realistic and reachable by any relayer or bridge user:

1. A fee recipient that has never registered storage for the bridged token will cause `ft_transfer` to fail on NEAR (NEP-141 requires prior `storage_deposit`).
2. Insufficient gas allocated to the sub-call (the static gas constants `MINT_TOKEN_GAS` / `FT_TRANSFER_GAS` are fixed and could be exhausted under congestion).
3. A token contract that panics for any internal reason (e.g., paused token, blacklisted recipient).

Any of these conditions, which a relayer applicant or token holder can trigger by simply not pre-registering storage, causes the silent loss.

### Recommendation

1. **Remove the `.detach()` on native-fee transfers** and chain them with the token-fee promise so a single callback can verify both succeeded.
2. **Move `env::log_str(ClaimFeeEvent)` into a `#[private]` callback** that fires only after both the native-fee and token-fee promises resolve successfully.
3. **Add a failure branch** in that callback that re-inserts the transfer message (or credits the fee to a claimable escrow) so the relayer can retry.
4. Apply the same pattern to `utxo_fin_transfer_fast` and `process_fin_transfer_to_other_chain`: replace `.detach()` with a chained callback that emits the event only on success and restores state on failure.

### Proof of Concept

1. Relayer calls `claim_fee` for a transfer whose `fee.native_fee > 0` and whose `fee_recipient` account exists on NEAR but has **never called `storage_deposit`** on the bridged token contract.
2. `claim_fee_callback` executes: `remove_transfer_message` removes the transfer; `send_fee_internal` is entered.
3. The native-fee `Promise::new(fee_recipient).transfer(...)` is `.detach()`-ed — result ignored.
4. `ClaimFeeEvent` is logged on-chain.
5. `ft_transfer(fee_recipient, token_fee, None)` is dispatched. Because the recipient has no storage registration, the NEP-141 token contract panics and the receipt fails.
6. No callback exists to catch this failure. The failed receipt is silently dropped.
7. **Result**: transfer message is gone, `ClaimFeeEvent` is on-chain, relayer received neither native fee nor token fee.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1133-1134)
```rust
        self.send_fee_internal(&transfer_message, fee_recipient, fee)
    }
```

**File:** near/omni-bridge/src/lib.rs (L2029-2053)
```rust
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
            required_balance = self
                .add_transfer_message(transfer_message.clone(), predecessor_account_id.clone())
                .saturating_add(required_balance);
        }

        self.update_storage_balance(
            predecessor_account_id,
            required_balance,
            env::attached_deposit(),
        );

        env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
```

**File:** near/omni-bridge/src/lib.rs (L2542-2558)
```rust
        self.send_tokens(
            fast_transfer.token_id.clone(),
            fast_transfer_status.relayer,
            amount,
            "",
        )
        .detach();

        env::log_str(
            &OmniBridgeEvent::UtxoTransferEvent {
                token_id: fast_transfer.token_id,
                amount,
                utxo_transfer_message: utxo_fin_transfer_msg,
                new_transfer_id: None,
            }
            .to_log_string(),
        );
```

**File:** near/omni-bridge/src/lib.rs (L2664-2673)
```rust
            } else if origin_chain == ChainKind::Near {
                Promise::new(fee_recipient.clone())
                    .transfer(NearToken::from_yoctonear(transfer_message.fee.native_fee.0))
                    .detach();
            } else {
                ext_token::ext(self.get_native_token_id(origin_chain))
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
```

**File:** near/omni-bridge/src/lib.rs (L2677-2682)
```rust
        env::log_str(
            &OmniBridgeEvent::ClaimFeeEvent {
                transfer_message: transfer_message.clone(),
            }
            .to_log_string(),
        );
```

**File:** near/omni-bridge/src/lib.rs (L2686-2698)
```rust
        if token_fee > 0 {
            if self.is_deployed_token(&token) {
                ext_token::ext(token)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient, U128(token_fee), None)
                    .into()
            } else {
                ext_token::ext(token)
                    .with_static_gas(FT_TRANSFER_GAS)
                    .with_attached_deposit(ONE_YOCTO)
                    .ft_transfer(fee_recipient, U128(token_fee), None)
                    .into()
            }
```
