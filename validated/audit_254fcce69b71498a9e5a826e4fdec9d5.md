### Title
Permissionless `request_refund` Allows Attacker to Front-Run Victim and Redirect BTC Refund to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`request_refund` is a fully permissionless public function that accepts any caller-supplied `refund_address` when `deposit_msg.refund_address` is `None`. An attacker who observes a victim's pending `request_refund` call (or independently derives the deposit data from on-chain events) can submit the same proof first with the attacker's own BTC address. The victim's subsequent call reverts with "Refund request already exists for this UTXO", and after the timelock the BTC is sent to the attacker.

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` carries no ownership check — it does not verify that the caller is the `recipient_id` named in `deposit_msg`, nor that the caller has any relationship to the deposited UTXO: [1](#0-0) 

The only caller restriction is that a custom `gas_fee` requires DAO/Operator role; the `refund_address` itself is unrestricted when `deposit_msg.refund_address` is `None`: [2](#0-1) 

The callback enforces uniqueness per UTXO — a second `request_refund` for the same UTXO is rejected: [3](#0-2) 

Once a refund request is stored, `execute_refund` is also permissionless — anyone can trigger it after the timelock: [4](#0-3) 

`execute_refund` builds the Bitcoin transaction paying `refund_request.refund_address` — the address the attacker supplied: [5](#0-4) 

The `LogDepositAddress` event emitted by `get_user_deposit_address` publicly broadcasts the full `deposit_msg` (including `recipient_id` and all fields needed to reconstruct the deposit path): [6](#0-5) 

This means the attacker does not even need to observe the victim's NEAR transaction in the mempool. They can reconstruct the `deposit_msg` from the emitted event, watch the BTC chain for an unfinalized deposit to the derived address, and submit `request_refund` with their own BTC address at any time before the victim.

### Impact Explanation

If the attacker's `request_refund` lands first, the stored `RefundRequest.refund_address` is the attacker's BTC address. After `unsafe_refund_timelock_sec` elapses, anyone (including the attacker) calls `execute_refund`, which constructs and signs a Bitcoin transaction paying the attacker. The victim's BTC is permanently transferred to the attacker. This is direct theft of user funds from the bridge's custody.

### Likelihood Explanation

- `deposit_msg.refund_address = None` is the natural default for users who do not pre-specify a refund address at deposit time.
- All inputs needed to call `request_refund` (`deposit_msg`, `tx_bytes`, `vout`, Merkle proof) are derivable from public on-chain data (NEAR events + BTC blockchain).
- The attacker does not need to race a specific NEAR block; they can submit at any time before the victim.
- The only protocol-level mitigation is the `unsafe_refund_timelock_sec` delay and DAO monitoring. If the DAO does not actively watch for suspicious refund requests, the attack succeeds silently. The victim, seeing their own `request_refund` revert, may check the registry, find a refund request exists for their UTXO, and incorrectly assume it is theirs.

### Recommendation

1. **Bind `request_refund` to the deposit owner**: require `env::predecessor_account_id() == deposit_msg.recipient_id` so only the intended recipient can open a refund request for their UTXO.
2. **Require a pre-authorized refund address**: mandate that `deposit_msg.refund_address` is always `Some(...)` (set at deposit time), eliminating the caller-supplied address path entirely. This is the two-step analog recommended in the reference report.
3. If caller-supplied addresses must be supported, at minimum emit a prominent event and require the victim to explicitly confirm the address before the request is stored.

### Proof of Concept

1. Alice calls `get_user_deposit_address(DepositMsg { recipient_id: "alice.near", refund_address: None, ... })`. The bridge emits `LogDepositAddress` with the full `deposit_msg`.
2. Alice sends BTC to the returned address. The deposit is never finalized by a relayer.
3. Attacker reads the `LogDepositAddress` event, fetches the BTC transaction from the Bitcoin chain, and constructs a valid `TxInclusionProof`.
4. Attacker calls `request_refund(deposit_msg, "attacker_btc_addr", tx_bytes, vout, proof, None)` — this succeeds and stores a `RefundRequest` with `refund_address = "attacker_btc_addr"`.
5. Alice calls `request_refund(deposit_msg, "alice_btc_addr", tx_bytes, vout, proof, None)` — this reverts in the callback: `"Refund request already exists for this UTXO"`.
6. After `unsafe_refund_timelock_sec` elapses (and assuming the DAO does not reject), attacker calls `execute_refund(utxo_storage_key, None)`.
7. The bridge builds and MPC-signs a Bitcoin transaction paying `"attacker_btc_addr"` the full deposit minus gas fee. Alice's BTC is stolen. [7](#0-6) [8](#0-7)

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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L18-44)
```rust
    pub(crate) fn internal_execute_refund(
        &mut self,
        utxo_storage_key: String,
        timelock_sec: u64,
        _chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let refund_request = self.load_refund_request_for_execute(&utxo_storage_key, timelock_sec);
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

        let mut psbt = PsbtWrapper::new(vec![outpoint], vec![refund_output]);
        psbt.set_input_utxo(vec![deposit_output]);

        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
    }
```
