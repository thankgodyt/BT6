### Title
Detached `send_tokens` Promise in UTXO Fast Transfer Finalization Causes Permanent Relayer Fund Loss on Failure — (`near/omni-bridge/src/lib.rs`)

---

### Summary

In `utxo_fin_transfer_fast()` and `process_fin_transfer_to_other_chain()`, the fast transfer state is permanently updated (removed or marked finalised) **before** the `send_tokens()` promise is confirmed to have succeeded. Because the promise is `.detach()`ed, any failure of the underlying token transfer is silently discarded. If `send_tokens` fails, the relayer's fronted tokens are permanently frozen inside the bridge contract with no recovery path. The code itself acknowledges this gap with an explicit `TODO` comment.

---

### Finding Description

**Vulnerable function 1: `utxo_fin_transfer_fast()`** [1](#0-0) 

The function first permanently mutates the fast-transfer accounting state:

- If the destination is NEAR: `remove_fast_transfer()` is called — the record is **deleted**.
- If the destination is another chain: `mark_fast_transfer_as_finalised()` is called — the record is **permanently locked**. [2](#0-1) 

Then it calls `send_tokens(...).detach()`, discarding the promise result entirely: [3](#0-2) 

If `send_tokens` fails (e.g., `ft_transfer` panics because the relayer's account has no storage registered with the UTXO token contract), the state mutation has already committed. The relayer's fronted tokens remain in the bridge with no mechanism to recover them.

The code itself flags this as unresolved: [4](#0-3) 

**Vulnerable function 2: `process_fin_transfer_to_other_chain()`**

The same pattern appears when a standard EVM→other-chain `fin_transfer` finalizes a pre-existing fast transfer. `send_tokens(...).detach()` is called and then `mark_fast_transfer_as_finalised()` is called in the same synchronous frame — the detached promise's failure cannot roll back the state update: [5](#0-4) 

**Contrast with the correctly handled path**

The non-UTXO fast-transfer-to-NEAR path (`fast_fin_transfer_to_near_callback`) correctly chains a `resolve_fast_transfer` callback that checks the promise result and reverts state on failure: [6](#0-5) 

The UTXO fast-transfer path has no equivalent callback.

---

### Impact Explanation

When `send_tokens` fails silently:

1. The fast transfer record is either deleted (`remove_fast_transfer`) or permanently locked (`mark_fast_transfer_as_finalised`). Neither state can be undone.
2. The relayer's fronted tokens (transferred to the bridge during `fast_fin_transfer`) remain in the bridge contract with no withdrawal or recovery function.
3. The UTXO connector's tokens (sent via `ft_transfer_call` to trigger finalization) are also consumed by the bridge with no refund.

This constitutes **permanent freezing of bridged funds** — the relayer's capital is irrecoverably locked.

---

### Likelihood Explanation

`send_tokens` with an empty `msg` calls `ft_transfer` on the UTXO token contract. `ft_transfer` panics (and thus fails) if the recipient (the relayer) does not have a storage deposit registered with that token contract. A trusted relayer who has not explicitly registered storage with the UTXO-chain token (e.g., the wrapped BTC token) will trigger this failure path during normal protocol operation — no malicious action is required. The UTXO connector is a legitimate, DAO-configured protocol participant whose `ft_transfer_call` is the standard finalization entry point.

---

### Recommendation

Replace the `.detach()` call in `utxo_fin_transfer_fast` with a chained callback (analogous to `resolve_fast_transfer`) that:

1. Checks whether `send_tokens` succeeded.
2. If it failed, reverts the fast-transfer state: re-insert the fast transfer record (or un-mark it as finalised) so the relayer's tokens can be recovered on a subsequent retry.

The same fix should be applied to the `process_fin_transfer_to_other_chain` fast-transfer branch.

---

### Proof of Concept

1. Trusted relayer calls `ft_transfer_call` on the UTXO token contract to the bridge with a `FastFinTransferMsg`, fronting `amount - fee` tokens to the recipient. The bridge stores the fast transfer record.
2. The UTXO connector later calls `ft_transfer_call` to the bridge with a `UtxoFinTransferMsg` matching the same transfer. This triggers `utxo_fin_transfer` → `utxo_fin_transfer_fast`.
3. Inside `utxo_fin_transfer_fast`, `remove_fast_transfer()` is called, deleting the record.
4. `send_tokens(token_id, relayer, amount, "").detach()` is dispatched. Because the relayer has no storage registered with the UTXO token contract, `ft_transfer` panics inside the detached promise.
5. The panic is silently discarded. The fast transfer record is gone. The relayer's fronted tokens remain in the bridge. No recovery is possible.

### Citations

**File:** near/omni-bridge/src/lib.rs (L2028-2041)
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
        } else {
```

**File:** near/omni-bridge/src/lib.rs (L2483-2486)
```rust
        if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            // TODO: check how to deal with failed send_tokens
            return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
        }
```

**File:** near/omni-bridge/src/lib.rs (L2518-2561)
```rust
    fn utxo_fin_transfer_fast(
        &mut self,
        fast_transfer: FastTransfer,
        fast_transfer_status: FastTransferStatus,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            !fast_transfer_status.finalised,
            BridgeError::FastTransferAlreadyFinalised.as_ref()
        );

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

        env::log_str(
            &OmniBridgeEvent::UtxoTransferEvent {
                token_id: fast_transfer.token_id,
                amount,
                utxo_transfer_message: utxo_fin_transfer_msg,
                new_transfer_id: None,
            }
            .to_log_string(),
        );

        PromiseOrPromiseIndexOrValue::Value(U128(0))
    }
```

**File:** near/omni-bridge/src/lib.rs (L2877-2912)
```rust

```
