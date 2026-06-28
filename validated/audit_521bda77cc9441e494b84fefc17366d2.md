### Title
`env::signer_account_id()` (tx.origin Equivalent) Used as Storage Payer in `ft_on_transfer` Enables Phishing-Based Storage Balance Drain — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`ft_on_transfer` in the NEAR bridge contract uses `env::signer_account_id()` — NEAR's direct analog of Solidity's `tx.origin` — to identify who pays for storage and native fees. A malicious contract can exploit this to silently drain a victim's storage balance (deposited NEAR tokens) and extract native fees on their behalf.

---

### Finding Description

In `ft_on_transfer`, the contract explicitly acknowledges that `sender_id` can be spoofed by an intermediate contract, and substitutes `env::signer_account_id()` instead: [1](#0-0) 

```rust
// We can't trust sender_id to pay for storage as it can be spoofed.
let signer_id = env::signer_account_id();
```

In NEAR's execution model:
- `env::predecessor_account_id()` = the immediate caller (analogous to `msg.sender`)
- `env::signer_account_id()` = the original transaction signer (analogous to `tx.origin`)

`signer_id` is then passed as the `storage_owner` into `init_transfer`, `fast_fin_transfer`, and `utxo_fin_transfer`: [2](#0-1) 

Inside `init_transfer`, the bridge checks and debits the `signer_id`'s storage balance to cover both on-chain storage costs and the `native_token_fee` specified in the transfer message: [3](#0-2) 

The `native_token_fee` is later claimable by the relayer via `sign_transfer`. This means the victim's deposited NEAR tokens flow to the relayer.

---

### Impact Explanation

**Attack scenario:**

1. Victim has a storage balance registered on the bridge (deposited NEAR tokens).
2. Victim is tricked into calling a malicious contract (e.g., a fake DeFi protocol or airdrop claimer).
3. The malicious contract calls `ft_transfer_call` on a legitimate, bridge-registered token (using the malicious contract's own token balance), targeting the bridge with a crafted `InitTransfer` message specifying:
   - `recipient` = attacker-controlled address on a foreign chain
   - `native_token_fee` = a large value up to the victim's storage balance
4. The token contract calls `bridge.ft_on_transfer(malicious_contract, amount, crafted_msg)`.
5. The bridge reads `env::signer_account_id()` = victim, and debits the victim's storage balance for both storage costs and the `native_token_fee`.
6. The attacker (acting as or colluding with a relayer) calls `sign_transfer` and claims the `native_token_fee` from the victim's balance.

**Result:** The victim's deposited NEAR tokens are transferred to the attacker without the victim's consent. The victim did not intend to initiate any bridge transfer.

---

### Likelihood Explanation

- Any user who has registered a storage balance on the bridge is a potential victim.
- The attacker only needs to deploy a malicious contract and hold a small amount of any bridge-registered token.
- The victim only needs to call one function on the malicious contract — a standard phishing scenario.
- The attacker must either be a registered relayer or collude with one to extract the native fee, which is a realistic assumption given the permissionless relayer registration model.

---

### Recommendation

Replace `env::signer_account_id()` with `sender_id` (the parameter passed by the token contract) for identifying the storage payer. The concern that `sender_id` can be spoofed is valid for *untrusted* token contracts, but the token contract is already identified via `env::predecessor_account_id()` and must be a registered bridge token for the transfer to succeed. Alternatively, require that the storage payer explicitly pre-authorize the transfer (e.g., via a separate storage deposit tied to a specific transfer intent), eliminating any reliance on the transaction origin.

---

### Proof of Concept

```
1. Attacker deploys MaliciousContract holding 1 USDC (bridge-registered token).
2. Victim calls MaliciousContract.trigger().
3. MaliciousContract calls:
     usdc.ft_transfer_call(
         receiver_id = "omni.bridge.near",
         amount = 1,
         msg = JSON({ InitTransfer: { recipient: "Eth:0xAttacker", fee: 0, native_token_fee: victim_storage_balance } })
     )
4. USDC contract calls bridge.ft_on_transfer("MaliciousContract", 1, msg).
5. Bridge reads env::signer_account_id() = victim.
6. Bridge debits victim's storage balance for native_token_fee.
7. Attacker (as relayer) calls sign_transfer and receives native_token_fee in NEAR.
``` [4](#0-3) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L253-283)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L523-583)
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

        let required_storage_balance =
            self.required_balance_for_init_transfer_message(transfer_message.clone());

        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));

        // Choose storage payer or whether to yield execution until storage is available
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
            PromiseOrPromiseIndexOrValue::Value(
                self.init_transfer_internal(transfer_message, signer_id),
```
