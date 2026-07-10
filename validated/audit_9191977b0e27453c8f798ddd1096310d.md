### Title
Permissionless `request_refund` Allows Attacker to Claim Refund Slot with Attacker-Controlled `refund_address`, Locking or Redirecting User BTC - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
`request_refund` is callable by any NEAR account. When a user's `DepositMsg` omits `refund_address` (the common case), an attacker who observes the publicly emitted `LogDepositAddress` event and the on-chain Bitcoin transaction can race to call `request_refund` for the same UTXO with their own Bitcoin address. The duplicate-key guard then blocks the legitimate user's subsequent call, and after `unsafe_refund_timelock_sec` elapses the attacker can execute the refund and receive the user's BTC.

### Finding Description

`request_refund` carries no caller-binding access control: [1](#0-0) 

Inside `request_refund_callback`, the `refund_address` is accepted verbatim from the caller. The only guard is that if `deposit_msg.refund_address` is `Some`, it must match — but when it is `None` (the optional field is skipped), any caller-supplied address is stored: [2](#0-1) 

After light-client verification succeeds, the request is inserted under the deterministic `utxo_storage_key = "{tx_id}@{vout}"`: [3](#0-2) 

Once the attacker's entry occupies that key, the legitimate user's callback panics on the duplicate check and their request is rejected. The attacker's stored `refund_address` is later used verbatim by `execute_refund` → `build_refund_output`: [4](#0-3) 

The `deposit_msg` needed to pass the script-pubkey check is publicly available: `get_user_deposit_address` emits it in a `LogDepositAddress` event, and relayer calls to `verify_deposit_v2` also expose it on-chain. The raw `tx_bytes` are visible on the Bitcoin blockchain. [5](#0-4) 

### Impact Explanation

An attacker who wins the race (or simply calls first, since NEAR has no traditional mempool ordering guarantee for users) stores a refund request pointing to their own Bitcoin address. After `unsafe_refund_timelock_sec` elapses without DAO/Operator intervention, `execute_refund` constructs and signs a Bitcoin transaction paying the attacker. The user's deposit BTC — minus the gas fee — is transferred to the attacker. The user cannot submit a competing request while the attacker's entry exists.

This constitutes attacker-triggered temporary locking of bridged funds (user is blocked from self-refunding) escalating to direct theft of underlying BTC if the DAO/Operator does not reject the request within the timelock window.

### Likelihood Explanation

All information required for the attack is publicly observable: the `DepositMsg` via NEAR events and the Bitcoin transaction via the Bitcoin blockchain. The attack requires no special role, no capital beyond the small NEAR storage deposit, and no cryptographic capability. The only mitigation is the `unsafe_refund_timelock_sec` window and DAO/Operator vigilance. An inattentive or overwhelmed operator, or a coordinated attack across many deposits simultaneously, removes this mitigation entirely.

### Recommendation

Bind the `refund_address` to the caller when `deposit_msg.refund_address` is `None`. For example, store `env::predecessor_account_id()` as the authorized submitter and require that only that account (or DAO/Operator) can later call `execute_refund` for the request. Alternatively, require that `deposit_msg.refund_address` always be set (non-optional) so the refund destination is fixed at deposit time and cannot be overridden by any caller.

### Proof of Concept

1. Alice calls `get_user_deposit_address` with `DepositMsg { recipient_id: "alice.near", refund_address: None, ... }`. The `LogDepositAddress` event is emitted, exposing the full `deposit_msg`.
2. Alice sends BTC to the derived address. The deposit is never finalized (e.g., wrong metadata).
3. Bob observes the NEAR event and the Bitcoin transaction. Bob calls `request_refund(deposit_msg=<Alice's>, refund_address="bob_btc_addr", tx_bytes=<Alice's tx>, vout=0, proof=<valid proof>)` with the required NEAR storage deposit.
4. Light-client verification passes. Bob's refund request is stored under `"{alice_txid}@0"` with `refund_address = "bob_btc_addr"`.
5. Alice calls `request_refund` with `refund_address = "alice_btc_addr"`. Her callback panics: `"Refund request already exists for this UTXO"`. Alice's NEAR storage deposit is consumed.
6. After `unsafe_refund_timelock_sec` elapses (assuming DAO/Operator does not reject), Bob calls `execute_refund("{alice_txid}@0")`. The bridge builds and MPC-signs a Bitcoin transaction paying `"bob_btc_addr"`. Alice's BTC is sent to Bob. [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L462-472)
```rust
    pub fn get_user_deposit_address(&self, deposit_msg: DepositMsg) -> String {
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path).to_string();
        Event::LogDepositAddress {
            deposit_msg,
            path,
            deposit_address: deposit_address.clone(),
        }
        .emit();
        deposit_address
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L294-308)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-578)
```rust
        let refund_request = RefundRequest {
            deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
            utxo_storage_key: utxo_storage_key.clone(),
            tx_bytes,
            vout,
            amount,
            refund_address,
            gas_fee: resolved_gas_fee,
            created_at_sec: nano_to_sec(env::block_timestamp()),
            executed: false,
        };

        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```
