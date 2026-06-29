### Title
Unvalidated BTC/Zcash Destination Address Permanently Locks User Tokens in NEAR Bridge - (File: `near/omni-types/src/lib.rs`)

---

### Summary

`OmniAddress::Btc` and `OmniAddress::Zcash` accept any arbitrary string as an address with no format validation. A user who supplies a malformed BTC or Zcash address when initiating a NEAR → UTXO transfer will have their tokens permanently locked in the bridge contract, with no on-chain recovery path.

---

### Finding Description

`UTXOChainAddress` is defined as a plain `String` alias: [1](#0-0) 

The `OmniAddress` enum wraps it without any structural constraint: [2](#0-1) 

The `FromStr` implementation for `OmniAddress` accepts any string for both UTXO chain variants: [3](#0-2) 

No checksum, prefix, length, or character-set check is applied. The bridge's `init_transfer` entry point performs only one guard on the recipient — that the destination chain is not NEAR itself: [4](#0-3) 

After that single check, `init_transfer_internal` locks the tokens and records the pending transfer: [5](#0-4) 

The only way to progress a NEAR → UTXO transfer is `submit_transfer_to_utxo_chain_connector`, which is restricted to trusted relayers: [6](#0-5) 

A trusted relayer that attempts to submit a transfer with an invalid address will be rejected by the UTXO connector. The callback re-inserts the transfer into `pending_transfers`: [7](#0-6) 

There is no user-callable cancel, withdraw, or refund function for pending transfers (confirmed by exhaustive grep across `near/omni-bridge/src/`). The transfer is permanently stuck.

The codebase itself documents this absence of validation in a test comment: [8](#0-7) 

---

### Impact Explanation

A user who initiates a NEAR → BTC or NEAR → Zcash transfer with a malformed address (e.g., `"btc:not_a_real_address"`) will have their tokens locked in the bridge contract indefinitely. No on-chain mechanism exists for the user to reclaim them. The locked tokens are removed from circulation on NEAR and never delivered on the UTXO chain. This constitutes **permanent freezing of bridged funds**.

---

### Likelihood Explanation

The attack surface is fully user-controlled and requires no special role or privilege. Any user calling `ft_transfer_call` with a malformed `OmniAddress::Btc` or `OmniAddress::Zcash` recipient triggers the lock. Accidental mistyping (e.g., wrong prefix, wrong character set, truncated address) is a realistic scenario for ordinary users, not just adversarial ones.

---

### Recommendation

Add format validation inside `OmniAddress::from_str` for the `"btc"` and `"zcash"` arms before constructing the variant. At minimum, enforce:

- **BTC**: Bech32/Bech32m prefix (`bc1`, `tb1`), valid character set, and length bounds per BIP-173 (max 90 chars).
- **Zcash**: Prefix check (`t1`, `t3`, `zs`, `u`) and length bounds per ZIP-316 for Unified Addresses.

Additionally, add a user-callable `cancel_pending_transfer` function that allows the original sender to reclaim tokens from a transfer that has remained in `pending_transfers` beyond a configurable timeout, as a defense-in-depth recovery path.

---

### Proof of Concept

1. User holds wrapped BTC tokens (`nbtc.bridge.near`) on NEAR.
2. User calls `ft_transfer_call` on `nbtc.bridge.near`:
   ```json
   {
     "receiver_id": "omni-bridge.near",
     "amount": "100000",
     "msg": "{\"InitTransfer\":{\"recipient\":\"btc:NOTAVALIDADDRESS!!!\",\"fee\":\"0\",\"native_token_fee\":\"0\"}}"
   }
   ```
3. `init_transfer` passes the only guard (`recipient.get_chain() != ChainKind::Near` → true for `Btc`).
4. `init_transfer_internal` locks 100,000 units and inserts the transfer into `pending_transfers`.
5. No trusted relayer will ever successfully submit this transfer — the UTXO connector rejects `"NOTAVALIDADDRESS!!!"`.
6. The callback re-inserts the transfer on any failed attempt.
7. No `cancel_transfer` or equivalent function exists on-chain.
8. The 100,000 units are permanently frozen in the bridge. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** near/omni-types/src/lib.rs (L171-171)
```rust
pub type UTXOChainAddress = String;
```

**File:** near/omni-types/src/lib.rs (L186-187)
```rust
    Btc(UTXOChainAddress),
    Zcash(UTXOChainAddress),
```

**File:** near/omni-types/src/lib.rs (L389-411)
```rust
impl FromStr for OmniAddress {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (chain, recipient) = input.split_once(':').unwrap_or(("eth", input));

        match chain {
            "eth" => Ok(Self::Eth(recipient.parse().map_err(stringify)?)),
            "near" => Ok(Self::Near(recipient.parse().map_err(stringify)?)),
            "sol" => Ok(Self::Sol(recipient.parse().map_err(stringify)?)),
            "arb" => Ok(Self::Arb(recipient.parse().map_err(stringify)?)),
            "base" => Ok(Self::Base(recipient.parse().map_err(stringify)?)),
            "bnb" => Ok(Self::Bnb(recipient.parse().map_err(stringify)?)),
            "pol" => Ok(Self::Pol(recipient.parse().map_err(stringify)?)),
            "hlevm" => Ok(Self::HyperEvm(recipient.parse().map_err(stringify)?)),
            "abs" => Ok(Self::Abs(recipient.parse().map_err(stringify)?)),
            "btc" => Ok(Self::Btc(recipient.to_string())),
            "zcash" => Ok(Self::Zcash(recipient.to_string())),
            "strk" => Ok(Self::Strk(recipient.parse().map_err(stringify)?)),
            "fogo" => Ok(Self::Fogo(recipient.parse().map_err(stringify)?)),
            _ => Err(format!("Chain {chain} is not supported")),
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L523-557)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/btc.rs (L23-101)
```rust
#[trusted_relayer]
#[near]
impl Contract {
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn submit_transfer_to_utxo_chain_connector(
        &mut self,
        transfer_id: TransferId,
        msg: String,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
        let transfer = self.get_transfer_message_storage(transfer_id);

        let message = serde_json::from_str::<TokenReceiverMessage>(&msg).expect("INVALID MSG");
        let amount = U128(transfer.message.amount.0 - transfer.message.fee.fee.0);

        if let Some(btc_address) = transfer.message.recipient.get_utxo_address() {
            if let TokenReceiverMessage::Withdraw {
                target_btc_address,
                input: _,
                output: _,
                max_gas_fee,
            } = message
            {
                require!(
                    btc_address == target_btc_address,
                    BridgeError::IncorrectTargetUtxoAddress.as_ref()
                );

                let max_gas_fee_msg = DestinationChainMsg::from_json(&transfer.message.msg)
                    .and_then(|s| s.max_gas_fee());

                if let Some(max_gas_fee_msg) = max_gas_fee_msg {
                    require!(
                        max_gas_fee.expect("max_gas_fee is missing") == max_gas_fee_msg,
                        "Invalid max gas fee"
                    );
                }
            } else {
                env::panic_str("Invalid message type");
            }
        } else {
            env::panic_str("Invalid destination chain");
        }

        if let Some(fee) = &fee {
            require!(
                &transfer.message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let chain_kind = transfer.message.get_destination_chain();
        let btc_account_id = self.get_utxo_chain_token(chain_kind);
        require!(
            self.get_token_id(&transfer.message.token) == btc_account_id,
            BridgeError::NativeTokenRequiredForChain.as_ref()
        );

        self.remove_transfer_message(transfer_id);

        let fee_recipient = fee_recipient.unwrap_or(env::predecessor_account_id());

        ext_token::ext(btc_account_id)
            .with_attached_deposit(ONE_YOCTO)
            .with_static_gas(FT_TRANSFER_CALL_GAS)
            .ft_transfer_call(self.get_utxo_chain_connector(chain_kind), amount, None, msg)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SUBMIT_TRANSFER_TO_BTC_CONNECTOR_CALLBACK_GAS)
                    .submit_transfer_to_btc_connector_callback(
                        transfer.message,
                        transfer.owner,
                        fee_recipient,
                    ),
            )
    }
```

**File:** near/omni-bridge/src/btc.rs (L111-126)
```rust
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

**File:** near/omni-tests/src/zcash_stale_transfer_poc.rs (L196-197)
```rust
        // A 500-char "Zcash UA" string. The bridge doesn't validate Zcash
        // address format — `OmniAddress::Zcash(String)` accepts anything —
```
