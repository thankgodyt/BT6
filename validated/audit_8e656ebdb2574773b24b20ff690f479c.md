### Title
Unchecked `send_tokens` Result in Fast-Transfer Relayer Repayment Causes Permanent Loss of Relayer Funds — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

In two code paths that repay a fast-transfer relayer after on-chain finalization, `send_tokens` is called with `.detach()` — its result is never inspected. State changes that permanently mark the fast transfer as finalised are committed in the same synchronous frame. If the token transfer fails, the relayer's fronted funds are lost forever with no recovery path. A developer-authored `// TODO` comment at the call site confirms the team is aware the failure case is unhandled.

---

### Finding Description

**Vulnerability class:** Callback/refund inconsistency — unchecked cross-contract call result leading to escrow mis-accounting and permanent fund loss.

**Instance 1 — `utxo_fin_transfer_fast`**

When a UTXO-chain fast transfer is finalized, the bridge calls `utxo_fin_transfer_fast`. The fast transfer record is removed or marked finalised *before* `send_tokens` is called, and the call is detached:

```rust
// near/omni-bridge/src/lib.rs  lines 2529-2548
let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
    self.remove_fast_transfer(&fast_transfer.id());   // state mutated first
    fast_transfer.amount
} else {
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // state mutated first
    U128(fast_transfer.amount_without_fee()...)
};

self.send_tokens(
    fast_transfer.token_id.clone(),
    fast_transfer_status.relayer,
    amount,
    "",
)
.detach();   // result never checked
```

The call site in `utxo_fin_transfer` that dispatches to this function already carries a developer acknowledgement:

```rust
// near/omni-bridge/src/lib.rs  line 2484
// TODO: check how to deal with failed send_tokens
return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
``` [1](#0-0) [2](#0-1) 

**Instance 2 — `process_fin_transfer_to_other_chain`**

When a non-UTXO fast transfer is finalized to another chain, the relayer repayment is also detached, and `mark_fast_transfer_as_finalised` is called immediately after in the same synchronous frame:

```rust
// near/omni-bridge/src/lib.rs  lines 2028-2040
if let Some(relayer) = recipient {
    self.send_tokens(token, relayer, U128(...), "")
        .detach();                                    // result never checked
    self.mark_fast_transfer_as_finalised(&fast_transfer.id());
}
``` [3](#0-2) 

In both cases, `send_tokens` internally issues either `ft_transfer` or `mint` depending on whether the token is a deployed bridge token: [4](#0-3) 

---

### Impact Explanation

A relayer fronts the full transfer amount (minus fee) to the recipient during the fast-transfer phase. When the canonical proof arrives and finalization occurs, the bridge is supposed to repay the relayer. If `send_tokens` fails (see likelihood below), the fast transfer is already marked finalised/removed — the relayer has no mechanism to retry or recover. The relayer permanently loses the full amount they fronted. This is a direct loss of bridged funds for a protocol participant.

**Impact: Critical** — permanent loss of bridged token funds for the relayer.

---

### Likelihood Explanation

`send_tokens` dispatches `ft_transfer` for non-deployed tokens. On NEAR, `ft_transfer` panics if the recipient account has not registered storage with the token contract. A relayer that registered storage for one token but not another, or whose storage registration expired, would trigger this failure. Additionally, if the bridge contract itself has insufficient attached deposit (ONE_YOCTO) due to a balance edge case, or if the token contract is paused/upgraded between the fast transfer and finalization, the call fails silently.

**Likelihood: Low** — requires a specific failure condition in the token transfer, but the scenario is realistic and the developer TODO confirms it is an acknowledged gap.

---

### Recommendation

Replace `.detach()` with a chained callback that checks the promise result. State mutations (`remove_fast_transfer` / `mark_fast_transfer_as_finalised`) should only be committed inside the callback after confirming the transfer succeeded. If the transfer fails, the fast transfer record should be restored so the relayer can retry or be compensated. This mirrors the pattern already used correctly in `submit_transfer_to_btc_connector_callback`:

```rust
// near/omni-bridge/src/btc.rs  lines 104-126
pub fn submit_transfer_to_btc_connector_callback(...) {
    if matches!(call_result, Ok(result) if result.0 > 0) {
        // success path: send fee
    } else {
        // failure path: restore transfer message
        self.add_transfer_message(transfer_msg, transfer_owner.clone());
    }
}
``` [5](#0-4) 

---

### Proof of Concept

1. Relayer calls `ft_transfer_call` on the token contract with a `FastFinTransferMsg` targeting a UTXO-chain recipient. The bridge records the fast transfer with the relayer's address.
2. The UTXO connector later calls `ft_transfer_call` back into the bridge with a `UtxoFinTransferMsg` matching the same UTXO ID, triggering `utxo_fin_transfer` → `utxo_fin_transfer_fast`.
3. Inside `utxo_fin_transfer_fast`, `remove_fast_transfer` (or `mark_fast_transfer_as_finalised`) is called, permanently updating state.
4. `send_tokens` is called with `.detach()`. If the relayer's account has no storage registered with the token contract, `ft_transfer` panics inside the async promise — but the detached promise's failure is never observed by the bridge.
5. The fast transfer record is gone. The relayer's fronted funds are permanently lost. The `UtxoTransferEvent` is emitted as if everything succeeded. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L2027-2041)
```rust
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
        } else {
```

**File:** near/omni-bridge/src/lib.rs (L2102-2117)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
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

**File:** near/omni-bridge/src/lib.rs (L2456-2486)
```rust
    fn utxo_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        signer_id: &AccountId,
        sender_id: &AccountId,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        let origin_chain = self
            .get_utxo_chain_by_token(&token_id)
            .near_expect(BridgeError::UtxoConfigMissing);
        let config = self
            .utxo_chain_connectors
            .get(&origin_chain)
            .near_expect(BridgeError::UtxoConfigMissing);
        require!(
            sender_id == &config.connector,
            BridgeError::SenderIsNotConnector.as_ref()
        );

        let fast_transfer = FastTransfer::from_utxo_transfer(
            utxo_fin_transfer_msg.clone(),
            token_id.clone(),
            amount,
            origin_chain,
        );

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

**File:** near/omni-bridge/src/btc.rs (L103-126)
```rust
    #[private]
    pub fn submit_transfer_to_btc_connector_callback(
        &mut self,
        transfer_msg: TransferMessage,
        transfer_owner: AccountId,
        fee_recipient: AccountId,
        #[callback_result] call_result: &Result<U128, PromiseError>,
    ) -> PromiseOrValue<()> {
        if matches!(call_result, Ok(result) if result.0 > 0) {
            let token_fee = transfer_msg.fee.fee.0;
            self.send_fee_internal(&transfer_msg, fee_recipient, token_fee)
        } else {
            let required_storage_balance =
                self.add_transfer_message(transfer_msg, transfer_owner.clone());

            self.update_storage_balance(
                transfer_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            );

            PromiseOrValue::Value(())
        }
    }
```
