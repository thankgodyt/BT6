Audit Report

## Title
Relayer Fee Silently Ignored in UTXO→NEAR Finalization Path — (`File: near/omni-bridge/src/lib.rs`)

## Summary
In `utxo_fin_transfer_to_near_callback`, the full bridged `amount` is sent to the recipient without deducting `utxo_fin_transfer_msg.relayer_fee`, and the relayer receives zero tokens. The `relayer_fee` field is present in `UtxoFinTransferMsg` and is correctly used in the UTXO→other-chain path, but is never read in the NEAR finalization path, causing concrete fee mis-accounting: the recipient is overpaid by exactly `relayer_fee` and the relayer is underpaid by the same amount.

## Finding Description
The UTXO→NEAR finalization flow is:

1. The UTXO connector calls `ft_transfer_call` on the bridge with `UtxoFinTransferMsg { relayer_fee, recipient: OmniAddress::Near(...), ... }`.
2. `utxo_fin_transfer` (L2456) validates the sender is the registered connector, then routes to `utxo_fin_transfer_to_near` (L2497–2506) when the recipient is a NEAR address.
3. `utxo_fin_transfer_to_near` (L2563) calls `check_or_pay_ft_storage` and chains to `utxo_fin_transfer_to_near_callback`.
4. Inside `utxo_fin_transfer_to_near_callback` (L975–1012), `send_tokens` is called with the full `amount` — not `amount - relayer_fee` — to the recipient. The `utxo_fin_transfer_msg.relayer_fee` field is never read.
5. `resolve_utxo_fin_transfer` (L1016–1044) only logs an event or handles refunds; it also never pays the relayer.

**Contrast with `utxo_fin_transfer_to_other_chain`** (L2595–2647): it explicitly stores `relayer_fee` in `TransferMessage.fee` (L2611–2614) so it can be claimed later via `claim_fee`.

**Contrast with `utxo_fin_transfer_fast`** (L2518–2561): it correctly sends the full amount to `fast_transfer_status.relayer` (L2542–2548).

The integration test at `near/omni-tests/src/utxo_fin_transfer.rs` (L218–223) encodes this behavior explicitly:
```rust
let (recipient_change, relayer_change) = match (is_fast_transfer, is_transfer_to_near) {
    (true, true)   => (0, amount),
    (true, false)  => (0, amount - utxo_msg.relayer_fee.0),
    (false, true)  => (amount, 0),   // ← relayer gets 0
    (false, false) => (0, 0),
};
```
For the `(false, true)` case (normal UTXO→NEAR), `relayer_change = 0` confirms the relayer receives nothing despite `relayer_fee` being set.

## Impact Explanation
This is a concrete fee mis-accounting issue matching the allowed Critical impact: "fee mis-accounting that changes user or protocol balances." The recipient receives `amount` tokens when they are entitled to only `amount - relayer_fee`. The relayer receives `0` when they are entitled to `relayer_fee`. Every non-fast UTXO→NEAR finalization with `relayer_fee > 0` results in a direct balance discrepancy of exactly `relayer_fee` tokens between the recipient (overpaid) and the relayer (underpaid). This also eliminates economic incentives for relayers to process UTXO→NEAR transfers.

## Likelihood Explanation
This triggers on every normal (non-fast-transfer) UTXO→NEAR finalization where `relayer_fee > 0`. The UTXO connector is a supported production bridge flow. Any user bridging BTC or Zcash to a NEAR address with a non-zero relayer fee will trigger this path. No special attacker capability is required — the flow is initiated by the UTXO connector calling `ft_transfer_call`, which is the standard production path. The test suite confirms the behavior is reproducible.

## Recommendation
In `utxo_fin_transfer_to_near_callback`, deduct `utxo_fin_transfer_msg.relayer_fee` from `amount` before calling `send_tokens` for the recipient, and separately send `relayer_fee` to the relayer (the `storage_owner` passed through the call chain). This mirrors how `utxo_fin_transfer_to_other_chain` handles the fee via `TransferMessage.fee`. Specifically:

```rust
let recipient_amount = U128(amount.0 - utxo_fin_transfer_msg.relayer_fee.0);
self.send_tokens(token_id.clone(), recipient, recipient_amount, &utxo_fin_transfer_msg.msg)
// then separately send relayer_fee to storage_owner
```

Also update the integration test assertion for `(false, true)` to expect `recipient_change = amount - relayer_fee` and `relayer_change = relayer_fee`.

## Proof of Concept
The existing integration test at `near/omni-tests/src/utxo_fin_transfer.rs` directly demonstrates the issue:

1. Set up a UTXO token and a trusted relayer as in `TestEnv::new`.
2. Call `verify_deposit` on the UTXO connector with `amount = 100_000_000` and `UtxoFinTransferMsg { relayer_fee: U128(1000), recipient: OmniAddress::Near(account_n(1)), ... }`.
3. Observe: `recipient_balance_after = recipient_balance_before + 100_000_000` (full amount, not `99_999_000`).
4. Observe: `relayer_balance_after = relayer_balance_before` (unchanged — relayer receives 0).
5. The test at L218–223 already asserts `(false, true) => (amount, 0)`, confirming this is the actual on-chain behavior. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L1016-1044)
```rust
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
    }
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

**File:** near/omni-tests/src/utxo_fin_transfer.rs (L218-223)
```rust
            let (recipient_change, relayer_change) = match (is_fast_transfer, is_transfer_to_near) {
                (true, true) => (0, amount),
                (true, false) => (0, amount - utxo_msg.relayer_fee.0),
                (false, true) => (amount, 0),
                (false, false) => (0, 0),
            };
```

**File:** near/omni-types/src/lib.rs (L515-522)
```rust
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct UtxoFinTransferMsg {
    pub utxo_id: UtxoId,
    pub recipient: OmniAddress,
    pub relayer_fee: U128,
    pub msg: String,
}
```
