### Title
Relayer Fee Not Deducted or Paid in UTXO-to-NEAR Transfer Path — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

In the UTXO-to-NEAR finalization path, `utxo_fin_transfer_to_near_callback` sends the full `amount` (inclusive of `relayer_fee`) to the recipient without deducting the fee, and never pays the relayer. This is the direct analog of the reported swap fee mis-accounting: the fee is acknowledged in the message but never subtracted from the user-facing output, so the relayer bears the cost of their own service.

---

### Finding Description

When a UTXO chain (BTC/Zcash) transfer targets a NEAR recipient, the execution path is:

```
utxo_fin_transfer  →  utxo_fin_transfer_to_near  →  utxo_fin_transfer_to_near_callback
```

Inside `utxo_fin_transfer_to_near_callback`, the full `amount` is forwarded to the recipient with no fee deduction:

```rust
// near/omni-bridge/src/lib.rs  lines 994-999
self.send_tokens(
    token_id.clone(),
    recipient,
    amount,                          // ← full amount, relayer_fee NOT subtracted
    &utxo_fin_transfer_msg.msg,
)
``` [1](#0-0) 

The `resolve_utxo_fin_transfer` callback that follows only handles the refund-on-failure case and emits a log; it contains no fee payment to the relayer at all. [2](#0-1) 

The `relayer_fee` field carried in `UtxoFinTransferMsg` is therefore silently discarded for NEAR-destination transfers.

**Contrast with the correct paths:**

- Standard EVM→NEAR `fin_transfer`: `process_fin_transfer_to_near` sends `amount_without_fee()` to the recipient, then `fin_transfer_send_tokens_callback` mints/transfers `fee.fee` to the fee recipient. [3](#0-2) [4](#0-3) 

- UTXO→other-chain: `utxo_fin_transfer_to_other_chain` stores `relayer_fee` in `TransferMessage.fee` so it can be claimed later via `claim_fee`. [5](#0-4) 

Neither mechanism exists in the UTXO-to-NEAR path.

**The integration test itself encodes the bug as expected behavior:**

```rust
// near/omni-tests/src/utxo_fin_transfer.rs  lines 218-223
let (recipient_change, relayer_change) = match (is_fast_transfer, is_transfer_to_near) {
    (true,  true)  => (0,      amount),                      // fast+NEAR: relayer reimbursed
    (true,  false) => (0,      amount - utxo_msg.relayer_fee.0), // fast+other: relayer reimbursed
    (false, true)  => (amount, 0),   // ← non-fast+NEAR: recipient gets ALL, relayer gets ZERO
    (false, false) => (0,      0),
};
``` [6](#0-5) 

The `(false, true)` branch confirms: in the non-fast UTXO-to-NEAR case the relayer receives `0` tokens regardless of the `relayer_fee` they specified.

---

### Impact Explanation

Every non-fast UTXO-to-NEAR transfer results in:

1. **Recipient over-payment**: the recipient receives `amount` tokens instead of `amount − relayer_fee`, gaining `relayer_fee` tokens they are not entitled to.
2. **Relayer fee theft / non-payment**: the relayer performs the finalization work and receives nothing. Over time this makes the UTXO-to-NEAR path economically unviable for relayers, or forces them to absorb the loss.

This is a fee mis-accounting issue that directly changes user and protocol balances — fitting the Critical impact scope.

---

### Likelihood Explanation

The vulnerable code executes on every ordinary (non-fast) UTXO-to-NEAR transfer. No special conditions are required beyond a user sending BTC or Zcash to a NEAR address. The UTXO connector is a registered, production-path contract; the path is fully reachable by any bridge user.

---

### Recommendation

In `utxo_fin_transfer_to_near_callback`, deduct `relayer_fee` from `amount` before calling `send_tokens`, and add a subsequent fee-payment step (analogous to `fin_transfer_send_tokens_callback`) that transfers `relayer_fee` to the relayer after the recipient transfer succeeds:

```rust
let amount_without_fee = U128(
    amount.0
        .checked_sub(utxo_fin_transfer_msg.relayer_fee.0)
        .expect("fee exceeds amount"),
);

self.send_tokens(token_id.clone(), recipient, amount_without_fee, &utxo_fin_transfer_msg.msg)
    .then(/* callback that pays relayer_fee to the relayer on success */)
```

Also update the integration test assertion for `(false, true)` to expect `recipient_change = amount − relayer_fee` and `relayer_change = relayer_fee`.

---

### Proof of Concept

1. User sends 100 000 000 satoshi-equivalent tokens via the BTC connector to a NEAR recipient, specifying `relayer_fee = 1 000`.
2. The UTXO connector calls `ft_transfer_call` on the bridge with `amount = 100_000_000`.
3. Bridge routes through `utxo_fin_transfer` → `utxo_fin_transfer_to_near` → `utxo_fin_transfer_to_near_callback`.
4. `send_tokens(..., amount = 100_000_000, ...)` is called — recipient receives the full `100_000_000`.
5. `resolve_utxo_fin_transfer` runs; no fee payment is issued.
6. Relayer balance: unchanged (receives `0`). Recipient balance: `+100_000_000` (should be `+99_999_000`). Relayer fee of `1 000` tokens is permanently lost to the relayer.

This matches the test's own assertion at line 221: `(false, true) => (amount, 0)`. [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L975-1012)
```rust
    #[private]
    pub fn utxo_fin_transfer_to_near_callback(
        &mut self,
        token_id: AccountId,
        recipient: AccountId,
        amount: U128,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
        origin_chain: ChainKind,
        storage_owner: &AccountId,
    ) -> PromiseOrValue<U128> {
        if !Self::check_storage_balance_result(0) {
            env::log_str(BridgeError::StorageRecipientOmitted.to_string().as_str());
            self.remove_fin_utxo_transfer(
                &utxo_fin_transfer_msg.get_transfer_id(origin_chain),
                storage_owner,
            );
            return PromiseOrValue::Value(amount);
        }

        self.send_tokens(
            token_id.clone(),
            recipient,
            amount,
            &utxo_fin_transfer_msg.msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(RESOLVE_UTXO_FIN_TRANSFER_GAS)
                .resolve_utxo_fin_transfer(
                    token_id,
                    amount,
                    utxo_fin_transfer_msg,
                    origin_chain,
                    storage_owner,
                ),
        )
        .into()
    }
```

**File:** near/omni-bridge/src/lib.rs (L1014-1043)
```rust
    #[allow(clippy::needless_pass_by_value)]
    #[private]
    pub fn resolve_utxo_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
        origin_chain: ChainKind,
        storage_owner: &AccountId,
    ) -> U128 {
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

**File:** near/omni-bridge/src/lib.rs (L1720-1733)
```rust
            // Send fee to the fee recipient
            if transfer_message.fee.fee.0 > 0 {
                if self.is_deployed_token(&token) {
                    ext_token::ext(token)
                        .with_static_gas(MINT_TOKEN_GAS)
                        .mint(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                } else {
                    ext_token::ext(token)
                        .with_attached_deposit(ONE_YOCTO)
                        .with_static_gas(FT_TRANSFER_GAS)
                        .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                }
```

**File:** near/omni-bridge/src/lib.rs (L1957-1966)
```rust
        self.send_tokens(
            token.clone(),
            recipient,
            U128(
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            ),
            &msg,
        )
```

**File:** near/omni-bridge/src/lib.rs (L2606-2614)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id.clone()),
            amount,
            recipient: utxo_fin_transfer_msg.recipient.clone(),
            fee: Fee {
                fee: utxo_fin_transfer_msg.relayer_fee,
                native_fee: U128(0),
            },
```

**File:** near/omni-tests/src/utxo_fin_transfer.rs (L218-234)
```rust
            let (recipient_change, relayer_change) = match (is_fast_transfer, is_transfer_to_near) {
                (true, true) => (0, amount),
                (true, false) => (0, amount - utxo_msg.relayer_fee.0),
                (false, true) => (amount, 0),
                (false, false) => (0, 0),
            };

            assert_eq!(
                relayer_balance_before.0,
                relayer_balance_after.0 - relayer_change,
                "Relayer balance is not correct"
            );
            assert_eq!(
                recipient_balance_before.0,
                recipient_balance_after.0 - recipient_change,
                "Recipient balance is not correct"
            );
```
