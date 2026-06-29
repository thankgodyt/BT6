### Title
Relayer Fee Not Paid to Relayer in UTXO→NEAR `utxo_fin_transfer_to_near_callback` — (`File: near/omni-bridge/src/lib.rs`)

### Summary

In the UTXO (BTC/Zcash) → NEAR finalization path, `utxo_fin_transfer_to_near_callback` sends the **full bridged amount** (including the `relayer_fee`) to the recipient, while the relayer receives nothing. This is the direct analog of H-4: a fee/recipient parameter is present in the message but is silently ignored during fund disbursement, causing incorrect accounting and eliminating relayer incentives.

### Finding Description

When a BTC or Zcash connector finalizes a transfer to a NEAR recipient, the flow is:

1. The UTXO connector calls `ft_transfer_call` on the bridge with a `UtxoFinTransferMsg` that includes `relayer_fee`.
2. `utxo_fin_transfer` dispatches to `utxo_fin_transfer_to_near`, which calls `check_or_pay_ft_storage` and then chains to `utxo_fin_transfer_to_near_callback`.
3. Inside `utxo_fin_transfer_to_near_callback`, `send_tokens` is called with the **full `amount`** — not `amount - relayer_fee`. [1](#0-0) 

The `relayer_fee` field from `UtxoFinTransferMsg` is never read or used in this callback. The relayer is never paid. [2](#0-1) 

The subsequent `resolve_utxo_fin_transfer` callback only logs an event and handles refunds — it also never pays the relayer. [3](#0-2) 

**Contrast with the UTXO→other-chain path**: `utxo_fin_transfer_to_other_chain` correctly stores `relayer_fee` in a `TransferMessage.fee` field so it can be claimed later via `claim_fee`. [4](#0-3) 

**Contrast with the fast-transfer UTXO path**: `utxo_fin_transfer_fast` correctly reimburses the relayer by sending them the full amount. [5](#0-4) 

### Impact Explanation

- The recipient receives `amount` tokens (the full bridged amount including the relayer fee), getting more than they are entitled to.
- The relayer receives `0` tokens for processing the BTC/Zcash → NEAR transfer.
- This is a direct balance mis-accounting: tokens that should flow to the relayer instead flow to the recipient.
- Relayers have no economic incentive to call `submit_transfer_to_utxo_chain_connector` or process UTXO→NEAR finalization, effectively breaking this bridge path.

### Likelihood Explanation

This triggers on every normal (non-fast-transfer) UTXO→NEAR finalization where `relayer_fee > 0`. Any user bridging BTC or Zcash to a NEAR address with a non-zero relayer fee will trigger this path. The UTXO connector is the entry point and it is a supported, production bridge flow. [6](#0-5) 

### Recommendation

In `utxo_fin_transfer_to_near_callback`, deduct `utxo_fin_transfer_msg.relayer_fee` from `amount` before calling `send_tokens` for the recipient, and separately send `relayer_fee` to the relayer (the `signer_id`/`storage_owner` passed through the call chain). This mirrors how `utxo_fin_transfer_to_other_chain` handles the fee via `TransferMessage.fee`. [7](#0-6) 

### Proof of Concept

1. A user initiates a BTC→NEAR transfer, specifying `relayer_fee = 1000` satoshis and `recipient = alice.near`.
2. The BTC connector calls `ft_transfer_call` on the bridge with `amount = 100_000_000` and `UtxoFinTransferMsg { relayer_fee: U128(1000), recipient: OmniAddress::Near("alice.near"), ... }`.
3. `utxo_fin_transfer` routes to `utxo_fin_transfer_to_near` → `utxo_fin_transfer_to_near_callback`.
4. `send_tokens(token_id, "alice.near", U128(100_000_000), ...)` is called — Alice receives the full `100_000_000`.
5. The relayer receives `0`. The `relayer_fee` field is never read.
6. `resolve_utxo_fin_transfer` logs the event and returns — no fee disbursement occurs. [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L975-1011)
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

**File:** near/omni-bridge/src/lib.rs (L2497-2506)
```rust
        if let OmniAddress::Near(recipient) = utxo_fin_transfer_msg.recipient.clone() {
            Self::utxo_fin_transfer_to_near(
                recipient,
                token_id,
                amount,
                utxo_fin_transfer_msg,
                origin_chain,
                signer_id,
            )
            .into()
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

**File:** near/omni-bridge/src/lib.rs (L2563-2593)
```rust
    fn utxo_fin_transfer_to_near(
        recipient: AccountId,
        token_id: AccountId,
        amount: U128,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
        origin_chain: ChainKind,
        storage_owner: &AccountId,
    ) -> Promise {
        let deposit_action = StorageDepositAction {
            account_id: recipient.clone(),
            token_id: token_id.clone(),
            storage_deposit_amount: None,
        };

        Self::check_or_pay_ft_storage(&deposit_action, &mut NearToken::from_yoctonear(0)).then(
            Self::ext(env::current_account_id())
                .with_static_gas(
                    env::prepaid_gas()
                        .saturating_sub(env::used_gas())
                        .saturating_sub(UTXO_FIN_TRANSFER_CALLBACK_GAS),
                )
                .utxo_fin_transfer_to_near_callback(
                    token_id,
                    recipient,
                    amount,
                    utxo_fin_transfer_msg,
                    origin_chain,
                    storage_owner,
                ),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L2606-2619)
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
            sender: OmniAddress::Near(env::predecessor_account_id()),
            msg: utxo_fin_transfer_msg.msg.clone(),
            destination_nonce: self
                .get_next_destination_nonce(utxo_fin_transfer_msg.get_destination_chain()),
            origin_transfer_id: Some(origin_transfer_id),
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
