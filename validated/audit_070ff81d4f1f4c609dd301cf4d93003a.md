### Title
Attacker Can Front-Run `request_refund` With Attacker-Controlled `refund_address` to Redirect BTC Refund - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
When a user deposits BTC using a `DepositMsg` with `refund_address: None`, the `request_refund` function accepts any caller-supplied `refund_address` without validating it against any user-controlled value. Because only one refund request can exist per UTXO, an attacker who front-runs the legitimate user's `request_refund` call with their own BTC address permanently occupies the refund slot. If the DAO/Operator does not reject the malicious request within the `unsafe_refund_timelock_sec` window, the attacker can execute the refund and redirect the user's BTC to their own address.

### Finding Description
`request_refund` is a permissionless function (no `#[trusted_relayer]` at the method level, no role check) callable by any NEAR account with sufficient attached deposit. [1](#0-0) 

Inside `internal_request_refund`, the `refund_address` parameter is only validated when `deposit_msg.refund_address` is `Some`. When it is `None`, any address is accepted without restriction: [2](#0-1) 

The `request_refund_callback` enforces a first-writer-wins rule: a second `request_refund` for the same UTXO is rejected outright: [3](#0-2) 

The stored `refund_address` is later used verbatim to build the Bitcoin output in `build_refund_output`, so whoever wins the first-writer race controls where the BTC goes: [4](#0-3) 

`execute_refund` is also permissionless (no method-level `#[trusted_relayer]`), so after the timelock the attacker can call it themselves, becoming the `caller` recorded in `BTCPendingInfo` and thus the account authorized to drive the MPC signing step: [5](#0-4) [6](#0-5) 

The only mitigation is the `unsafe_refund_timelock_sec` window, which is explicitly intended to give DAO/Operator time to call `reject_refund`. If they do not act in time, the attacker proceeds unimpeded: [7](#0-6) 

### Impact Explanation
If the DAO/Operator fails to reject the malicious request within `unsafe_refund_timelock_sec`, the attacker calls `execute_refund` (permissionless), drives the MPC signing as the `BTCPendingInfo` owner, broadcasts the signed transaction, and receives the full deposit amount minus gas fee at their own Bitcoin address. The legitimate user's BTC is permanently lost. This matches the **Medium** impact category: attacker-triggered stuck/redirected bridge state requiring operator intervention, with escalation to Critical loss if the operator window is missed.

### Likelihood Explanation
All inputs required to call `request_refund` are public: `deposit_msg` is broadcast when the user calls `get_user_deposit_address`; `tx_bytes` and the Merkle proof are on the Bitcoin blockchain. An attacker passively monitoring Bitcoin for deposits to bridge-derived addresses can construct and submit the malicious `request_refund` before the legitimate user does. The only cost is the attached NEAR storage deposit, which is negligible relative to any meaningful BTC deposit.

### Recommendation
Bind the `refund_address` to the depositor at deposit-address-derivation time rather than at refund-request time. Concretely, require `deposit_msg.refund_address` to be `Some` before a permissionless `request_refund` is accepted; callers without a pre-authorized address should only be able to request a refund to the address embedded in the `deposit_msg`. Alternatively, restrict `request_refund` to the original `recipient_id` recorded in `deposit_msg` when no pre-authorized `refund_address` is present, so an attacker cannot occupy the refund slot with an arbitrary address.

### Proof of Concept
1. Alice deposits BTC using `DepositMsg { recipient_id: "alice.near", refund_address: None, ... }`. The deposit address is derived from this message and is public.
2. The relayer does not call `verify_deposit` (e.g., it is down).
3. Attacker Eve observes the confirmed BTC deposit on-chain, reconstructs `deposit_msg` from the public `LogDepositAddress` event, and calls:
   ```
   request_refund(
       deposit_msg = { recipient_id: "alice.near", refund_address: None, ... },
       refund_address = "bc1q<eve_address>",
       tx_bytes = <from Bitcoin>,
       vout = 0,
       proof = <from Bitcoin>,
       gas_fee = None
   )
   ```
   with sufficient attached NEAR deposit. This succeeds because `deposit_msg.refund_address` is `None`, so no address validation is performed.
4. Alice subsequently calls `request_refund` with her own address — it fails: `"Refund request already exists for this UTXO"`.
5. The DAO/Operator does not notice or does not act within `unsafe_refund_timelock_sec`.
6. Eve calls `execute_refund(utxo_storage_key)`. She becomes the `caller` in `BTCPendingInfo`.
7. Eve calls `sign_btc_transaction` (she owns the pending info). MPC signs the transaction paying `bc1q<eve_address>`.
8. Eve broadcasts the transaction. Alice's BTC is sent to Eve's address.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-535)
```rust
    #[allow(clippy::too_many_arguments)]
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L223-228)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L293-308)
```rust
    /// Build a transparent refund output paying `refund_amount` to `refund_address`.
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L339-375)
```rust
        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);

        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
            vutxos: vec![vutxo],
            signatures: vec![None; 1],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };

        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```
