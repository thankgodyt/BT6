### Title
Partial `ft_on_transfer` Refund Leaves Bridged Tokens Permanently Stuck in `omni-bridge` Contract — (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

The `is_refund_required()` helper only triggers a bridge-state revert when `ft_transfer_call` reports **zero** tokens used. When a recipient's `ft_on_transfer` returns a **partial** unused amount, the NEP-141 token contract refunds those tokens back to the bridge, but the bridge's callbacks (`fin_transfer_send_tokens_callback`, `resolve_fast_transfer`, `resolve_utxo_fin_transfer`) treat the transfer as fully successful and never forward the partial refund to the original sender. The refunded tokens are permanently stuck in the bridge contract.

---

### Finding Description

When a cross-chain transfer includes a non-empty `msg` field, `send_tokens()` calls `ft_transfer_call` on the token contract instead of `ft_transfer`. [1](#0-0) 

Under NEP-141, the recipient's `ft_on_transfer` returns the number of tokens it did **not** use (the refund amount). The token contract then refunds that amount back to the bridge (the caller of `ft_transfer_call`) and returns the number of tokens that **were** used to the bridge's callback.

The bridge's `is_refund_required()` reads this result and only triggers a revert when the used amount equals zero: [2](#0-1) 

If the recipient uses, say, 998 out of 999 tokens and returns 1 unused, `ft_transfer_call` reports `998` used. `is_refund_required` sees `998 != 0` and returns `false`. The bridge proceeds as if the transfer fully succeeded, sends the fee to the relayer, and emits `FinTransferEvent`. The 1 token refunded by the NEP-141 contract to the bridge address is never forwarded to the original sender and has no recovery path in the bridge's accounting.

This affects three callback paths that all share the same `is_refund_required` logic:

1. **`fin_transfer_send_tokens_callback`** — regular inbound finalization with `msg` [3](#0-2) 

2. **`resolve_fast_transfer`** — fast-transfer path with `msg` [4](#0-3) 

3. **`resolve_utxo_fin_transfer`** — UTXO-chain finalization with `msg` [5](#0-4) 

The existing integration test suite **explicitly documents this behavior** as an accepted outcome: [6](#0-5) 

The test case with `return_value: U128(1)` (1 token returned unused by the recipient) shows `expected_locker_balance: 1` — confirming 1 token is left stranded in the bridge contract.

---

### Impact Explanation

Bridged tokens that are partially rejected by the recipient's `ft_on_transfer` are permanently locked inside the `omni-bridge` contract. The original cross-chain sender receives fewer tokens than were bridged, with no automatic recovery. The bridge's `locked_tokens` accounting is already decremented (for native tokens) or the bridge tokens are already minted (for deployed tokens) before the `ft_transfer_call`, so the accounting does not reflect the stuck balance. The only recovery path is a DAO-privileged `transfer_token_as_dao` call, which is not automatic and requires admin intervention.

This constitutes **permanent freezing of bridged funds** for any transfer that includes a `msg` field where the recipient partially rejects the tokens.

---

### Likelihood Explanation

Any user who initiates a cross-chain transfer with a non-empty `msg` field targeting a NEAR contract that partially consumes tokens triggers this path. This is a realistic scenario for DeFi integrations (e.g., a DEX or lending protocol that accepts only part of the offered tokens). The user controls the `msg` and recipient fields on the source chain, and the bridge provides no protection against partial refunds. No special privileges are required.

---

### Recommendation

In each of the three callback functions, after `is_refund_required` returns `false`, read the actual used amount from the promise result and compare it to the sent amount. If `used_amount < sent_amount`, the difference (`sent_amount - used_amount`) was refunded to the bridge and must be forwarded to the original sender (or burned if it is a deployed bridge token). Concretely:

- Replace the binary `is_refund_required` check with a function that returns the actual used amount.
- If `used_amount == 0`: full revert (existing behavior).
- If `0 < used_amount < sent_amount`: partial refund — send `sent_amount - used_amount` back to the original sender (or burn if deployed token).
- If `used_amount == sent_amount`: full success (existing behavior).

---

### Proof of Concept

The existing test at `near/omni-tests/src/fin_transfer.rs:533-544` already demonstrates the bug:

```
amount = 1000, fee = 1
msg.return_value = U128(1)   // recipient returns 1 token unused

expected_recipient_balance = 998   // recipient got 998 (not 999)
expected_relayer_balance   = 1     // relayer got fee
expected_locker_balance    = 1     // 1 token stuck in bridge ← BUG
``` [6](#0-5) 

The bridge emits `FinTransferEvent` (success) despite 1 token being silently absorbed. The original cross-chain sender has no recourse.

### Citations

**File:** near/omni-bridge/src/lib.rs (L906-911)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
        }
```

**File:** near/omni-bridge/src/lib.rs (L1024-1043)
```rust
        let is_ft_transfer_call = !utxo_fin_transfer_msg.msg.is_empty();
        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fin_utxo_transfer(
                &utxo_fin_transfer_msg.get_transfer_id(origin_chain),
                storage_owner,
            );
            amount
        } else {
            env::log_str(
                &OmniBridgeEvent::UtxoTransferEvent {
                    token_id,
                    amount,
                    utxo_transfer_message: utxo_fin_transfer_msg,
                    new_transfer_id: None,
                }
                .to_log_string(),
            );

            U128(0)
        }
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

**File:** near/omni-bridge/src/lib.rs (L1784-1804)
```rust
    fn is_refund_required(is_ft_transfer_call: bool) -> bool {
        if is_ft_transfer_call {
            match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
                Ok(value) => {
                    if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                        // Normal case: refund if the used token amount is zero
                        // The amount can be zero if the `ft_on_transfer` in the receiver contract returns an amount instead of `0`, or if it panics.
                        amount.0 == 0
                    } else {
                        // Unexpected case: don't refund
                        false
                    }
                }
                // Unexpected case: don't refund
                Err(_) => false,
            }
        } else {
            // Not ft_transfer_call: don't refund
            false
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L2107-2117)
```rust
        } else {
            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(ft_transfer_call_gas)
                .ft_transfer_call(recipient, amount, None, msg.to_string())
        }
```

**File:** near/omni-tests/src/fin_transfer.rs (L533-544)
```rust
    #[case(FinTransferWithMsgCase {
        storage_deposit_accounts: vec![(relayer_account_id(), true)],
        amount: 1000,
        fee: 1,
        msg: TokenReceiverMessage {
            return_value: U128(1),
            panic: false,
            extra_msg: String::new(),
        },
        expected_recipient_balance: 998,
        expected_relayer_balance: 1,
        expected_locker_balance: 1,
```
