### Title
`init_transfer` Accepts Transfers to Chains Without a Registered Factory, Enabling Permanent Fund Freezing — (File: near/omni-bridge/src/lib.rs)

---

### Summary

The `init_transfer` function in the NEAR omni-bridge contract does not validate that the destination chain has a registered factory before accepting and locking user tokens. Any unprivileged user can initiate a transfer to a chain with no registered factory, permanently locking (or burning) their tokens with no user-accessible recovery path.

---

### Finding Description

**Root cause — missing factory check in `init_transfer`:**

`init_transfer` (the outbound transfer entry point, reached via `ft_on_transfer`) performs only one chain-level check:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
``` [1](#0-0) 

It does **not** verify that the destination chain has a registered factory in `self.factories`. Immediately after this single check, `init_transfer_internal` is called, which locks native tokens or burns deployed tokens:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
``` [2](#0-1) 

**Contrast with the inbound path:**

`fin_transfer_callback` (the inbound path) correctly validates the emitter against the registered factory map before doing anything:

```rust
require!(
    self.factories
        .get(&init_transfer.emitter_address.get_chain())
        == Some(init_transfer.emitter_address),
    BridgeError::UnknownFactory.as_ref()
);
``` [3](#0-2) 

The outbound path has no equivalent guard.

**No user-accessible cancel mechanism:**

Once tokens are locked/burned and the transfer is stored in `pending_transfers`, the only removal paths are:
- `claim_fee_callback` — requires a cryptographic proof from the destination chain (impossible if no factory exists there)
- `sign_transfer_callback` — only removes the entry if `fee.is_zero()`, and even then the tokens are already gone
- `transfer_token_as_dao` — DAO-only emergency function, not a user recovery path [4](#0-3) [5](#0-4) 

**`ChainKind` includes chains that may lack a registered factory:**

The `OmniAddress` parser accepts all variants of `ChainKind` (Eth, Sol, Arb, Base, Bnb, Pol, HyperEvm, Abs, Strk, Fogo, Btc, Zcash). Not all of these chains are guaranteed to have a registered factory at all times (e.g., newly added chains like Fogo, or chains whose factory was removed). [6](#0-5) 

---

### Impact Explanation

- **Native tokens** (e.g., USDC): permanently locked in the bridge with no user-accessible recovery. DAO intervention via `transfer_token_as_dao` is the only escape hatch.
- **Deployed (bridge-minted) tokens**: burned by `burn_tokens_if_needed` and permanently destroyed — no recovery is possible even with DAO intervention.

This constitutes **permanent freezing or loss of bridged funds**, which falls squarely within the Critical impact scope.

---

### Likelihood Explanation

The `ChainKind` enum is extended as new chains are onboarded. There is a window between when a chain variant is added to the type system and when its factory is deployed and registered. During this window, any user who specifies that chain as a destination will permanently lose their tokens. Additionally, if a factory is ever removed (e.g., a chain is deprecated), all subsequent `init_transfer` calls to that chain will silently lock funds.

The entry path is fully public: any token holder can call `ft_transfer_call` on any NEP-141 token, triggering `ft_on_transfer` → `init_transfer`. [7](#0-6) 

---

### Recommendation

Add a factory existence check at the top of `init_transfer`, mirroring the guard already present in `fin_transfer_callback`:

```rust
require!(
    self.factories
        .get(&init_transfer_msg.get_destination_chain())
        .is_some(),
    BridgeError::UnknownFactory.as_ref()
);
```

Additionally, consider adding a user-accessible `cancel_transfer` function that returns locked tokens to the sender for transfers that have not yet been signed.

---

### Proof of Concept

1. Assume chain `Fogo` (or any `ChainKind` variant) has no registered factory in `self.factories`.
2. User calls `ft_transfer_call` on a token contract with:
   ```json
   {
     "receiver_id": "omni.bridge.near",
     "amount": "1000000",
     "msg": "{\"InitTransfer\":{\"recipient\":\"fogo:0xdeadbeef...\",\"fee\":\"0\",\"native_token_fee\":\"0\"}}"
   }
   ```
3. `ft_on_transfer` → `init_transfer` runs. The only check (`!= Near`) passes.
4. `init_transfer_internal` locks (native token) or burns (deployed token) the user's 1,000,000 tokens.
5. The transfer is stored in `pending_transfers`.
6. No relayer can call `sign_transfer` successfully if the token has no address for Fogo; or if it does, the MPC-signed payload can never be finalized on Fogo (no factory contract exists there).
7. The user has no mechanism to cancel the transfer or recover their tokens.
8. Funds are permanently frozen. [8](#0-7) [9](#0-8)

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-283)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
            }
            BridgeOnTransferMsg::FastFinTransfer(fast_fin_transfer_msg) => {
                self.fast_fin_transfer(token_id, amount, signer_id, fast_fin_transfer_msg)
            }
            BridgeOnTransferMsg::UtxoFinTransfer(utxo_fin_transfer_msg) => self.utxo_fin_transfer(
                token_id,
                amount,
                &signer_id,
                &sender_id,
                utxo_fin_transfer_msg,
            ),
            BridgeOnTransferMsg::SwapMigratedToken => {
                self.swap_migrated_token(sender_id, token_id, amount)
                    .detach();
                PromiseOrPromiseIndexOrValue::Value(U128(0))
            }
        };

        promise_or_promise_index_or_value.as_return();
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

**File:** near/omni-bridge/src/lib.rs (L648-668)
```rust
    #[private]
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L708-713)
```rust
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1511-1529)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn transfer_token_as_dao(
        &mut self,
        token: AccountId,
        amount: U128,
        recipient: AccountId,
        msg: Option<String>,
    ) -> Promise {
        if let Some(msg) = msg {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_CALL_GAS)
                .ft_transfer_call(recipient, amount, None, msg)
        } else {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        }
```

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
    }
```

**File:** near/omni-types/src/lib.rs (L392-411)
```rust
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
