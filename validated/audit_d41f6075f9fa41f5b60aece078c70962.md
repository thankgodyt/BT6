### Title
Double-Spend via Finalization Record Removal on `ft_transfer_call` Rejection — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

When `fin_transfer` finalizes an inbound transfer to a NEAR recipient with a non-empty `msg` field, the bridge uses `ft_transfer_call` to deliver tokens. If the recipient contract's `ft_on_transfer` rejects all tokens, `fin_transfer_send_tokens_callback` burns the refunded tokens and then **removes the transfer from `finalised_transfers`**. This erasure of the replay-protection record allows the same foreign-chain proof to be submitted a second time, enabling a double-spend of bridged tokens.

---

### Finding Description

The inbound finalization flow for a NEAR recipient with a non-empty `msg` is:

**Step 1 — Mark finalized (replay guard set):**
`process_fin_transfer_to_near` calls `add_fin_transfer`, which inserts the `TransferId` into `finalised_transfers`. [1](#0-0) 

**Step 2 — Deliver tokens via `ft_transfer_call`:**
`send_tokens` mints tokens to the bridge contract itself, then calls `ft_transfer_call` to the recipient. The recipient's `ft_on_transfer` controls how many tokens are "used". [2](#0-1) 

**Step 3 — Callback evaluates result:**
`is_refund_required` returns `true` when the `ft_transfer_call` result is `0` — meaning the receiver returned all tokens (used none). [3](#0-2) 

**Step 4 — Replay guard erased:**
When `is_refund_required` is `true`, `fin_transfer_send_tokens_callback` burns the refunded tokens and then calls `remove_fin_transfer`, which **deletes the `TransferId` from `finalised_transfers`**. [4](#0-3) 

After step 4, `add_fin_transfer` will succeed again for the same `TransferId` because the set no longer contains it: [5](#0-4) 

The prover verifies the proof against immutable foreign-chain state, so the same proof passes verification on the second submission. The bridge then mints tokens a second time and delivers them to the recipient.

The `msg` field that triggers `ft_transfer_call` is user-controlled: it originates from the `message` field of the foreign-chain `InitTransfer` event, which the attacker sets when initiating the transfer. [6](#0-5) 

---

### Impact Explanation

**Critical — unauthorized minting / double-spend of bridged tokens.**

For deployed (bridged) tokens, the sequence is:

| Submission | Mint | Recipient action | Burn | Net supply change |
|---|---|---|---|---|
| First | +N | Reject (return N) | −N | 0 |
| Second | +N | Accept (keep N) | 0 | +N |

The foreign chain locked/burned tokens exactly once, but the NEAR bridge mints them twice (once burned, once kept). The attacker ends up holding N tokens backed by zero foreign-chain collateral — inflating the bridged token supply and stealing value from the bridge's reserves.

---

### Likelihood Explanation

**Medium.** The attacker needs to:

1. **Control a NEAR recipient contract** — trivial; any user can deploy a contract.
2. **Set a non-empty `msg`** — trivial; the `message` field in `initTransfer` on the EVM side is freely chosen by the sender.
3. **Have `ft_on_transfer` reject on the first call** — trivial for a malicious contract.
4. **Cause `fin_transfer` to be called a second time** — realistic: after `remove_fin_transfer` erases the record, any relayer monitoring `finalised_transfers` will see the transfer as unfinalized and resubmit the proof in good faith. The attacker does not need to be a trusted relayer themselves; they only need to control the recipient contract.

---

### Recommendation

**Do not remove the `TransferId` from `finalised_transfers` when `ft_transfer_call` fails.** The finalization record is the sole replay-protection gate for inbound transfers; erasing it on delivery failure reopens the proof for reuse.

Instead, on `ft_transfer_call` failure:
- Keep the `TransferId` in `finalised_transfers` permanently.
- Store the undelivered tokens in a claimable balance for the recipient (or revert to a simple `ft_transfer` without `msg`).
- Emit a `FailedFinTransferEvent` so off-chain systems can alert without resubmitting.

---

### Proof of Concept

```
1. Attacker deploys `attacker.near` — a NEAR contract whose `ft_on_transfer`
   returns `amount` (full rejection) on the first call, and `0` (accept) on
   the second call.

2. Attacker calls `initTransfer` on the EVM OmniBridge:
     recipient = "attacker.near"
     msg       = "trigger"          // non-empty → ft_transfer_call path
     amount    = 1_000_000

3. A trusted relayer observes the EVM event and calls `fin_transfer` on NEAR
   with the valid proof.

4. Bridge executes:
     add_fin_transfer(transfer_id)          // replay guard set
     mint(bridge, 1_000_000)                // tokens minted to bridge
     ft_transfer_call(attacker.near, ...)   // delivery attempt

5. `attacker.near::ft_on_transfer` returns 1_000_000 (full rejection).
   Tokens are refunded to bridge.

6. `fin_transfer_send_tokens_callback` runs:
     burn_tokens_if_needed(1_000_000)       // tokens destroyed
     remove_fin_transfer(transfer_id)       // ← replay guard ERASED

7. Relayer's monitor queries `is_transfer_finalised(transfer_id)` → false.
   Relayer resubmits `fin_transfer` with the same proof.

8. Bridge executes again:
     add_fin_transfer(transfer_id)          // succeeds — record was removed
     mint(bridge, 1_000_000)                // tokens minted again
     ft_transfer_call(attacker.near, ...)

9. `attacker.near::ft_on_transfer` returns 0 (accept).
   Attacker keeps 1_000_000 tokens.

Result: 1_000_000 tokens minted with no additional EVM collateral.
        Bridged token supply inflated; bridge reserves drained.
```

### Citations

**File:** near/omni-bridge/src/lib.rs (L722-732)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };
```

**File:** near/omni-bridge/src/lib.rs (L1702-1714)
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
```

**File:** near/omni-bridge/src/lib.rs (L1784-1803)
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
```

**File:** near/omni-bridge/src/lib.rs (L1875-1875)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
```

**File:** near/omni-bridge/src/lib.rs (L2094-2101)
```rust
            ext_token::ext(token)
                .with_attached_deposit(deposit)
                .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
                .mint(
                    recipient,
                    amount,
                    (!msg.is_empty()).then(|| msg.to_string()),
                )
```

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```
