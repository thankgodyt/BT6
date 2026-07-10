### Title
Any Caller Can Redirect a User's BTC Refund to an Arbitrary Address via `request_refund` Race Condition - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
The `request_refund` function is publicly callable and allows any caller to specify an arbitrary BTC `refund_address` for a deposit UTXO when `deposit_msg.refund_address` is `None`. Because only one refund request can exist per UTXO, an attacker who races to call `request_refund` first permanently sets the refund destination to their own BTC address, stealing the user's deposited BTC.

### Finding Description
`request_refund` accepts a caller-supplied `refund_address` with no ownership check against the deposit's `recipient_id`: [1](#0-0) 

Inside `request_refund_callback`, the only guard against a duplicate request is a first-come-first-served key check: [2](#0-1) 

When `deposit_msg.refund_address` is `None`, the caller's address is stored verbatim with no validation that the caller is the deposit owner: [3](#0-2) [4](#0-3) 

Later, `execute_refund` (also publicly callable) builds the Bitcoin output directly from the stored `refund_address`: [5](#0-4) [6](#0-5) 

The `unsafe_refund_timelock_sec` path is taken for all caller-supplied addresses, giving the DAO/Operator a window to reject — but this is not a guaranteed protection: [7](#0-6) 

### Impact Explanation
An attacker who wins the race to call `request_refund` for a deposit whose `deposit_msg.refund_address` is `None` permanently sets the BTC refund destination to their own address. Once the `unsafe_refund_timelock_sec` elapses, anyone (including the attacker) can call `execute_refund`, causing the bridge's MPC layer to sign and broadcast a Bitcoin transaction paying the attacker's address. The legitimate depositor loses their entire BTC principal minus the gas fee. This constitutes a direct, irreversible theft of user funds from the bridge's custody.

### Likelihood Explanation
The `deposit_msg` used to derive the deposit address is emitted publicly via the `LogDepositAddress` event when `get_user_deposit_address` is called: [8](#0-7) 

Any deposit that is not immediately finalized via `verify_deposit` (e.g., due to relayer latency, low BTC confirmations, or a failed proof submission) is vulnerable. The attacker only needs to submit a valid Merkle proof — all data is publicly available on the Bitcoin blockchain. The sole mitigation is the `unsafe_refund_timelock_sec` window during which the DAO/Operator must notice and call `reject_refund`. If the operator is offline, slow, or the timelock is short, the attack succeeds. The storage deposit required is a minor cost easily offset by any non-trivial BTC deposit amount.

### Recommendation
- Bind the refund address to the deposit owner: require the caller of `request_refund` to be the `recipient_id` encoded in `deposit_msg`, or cryptographically prove ownership.
- Alternatively, mandate that `deposit_msg.refund_address` is always set at deposit time (non-`None`), so the refund destination is fixed at address-derivation time and cannot be overridden by a third party.
- If open submission must be preserved, emit a prominent on-chain event and require an explicit on-chain acknowledgment from `deposit_msg.recipient_id` before the request becomes executable.

### Proof of Concept
1. User generates a deposit address via `get_user_deposit_address(deposit_msg)` where `deposit_msg.refund_address = None`. The event reveals `deposit_msg` publicly.
2. User sends BTC to the derived address. The deposit is not yet finalized (relayer has not called `verify_deposit`).
3. Attacker observes the BTC transaction on-chain, reconstructs `deposit_msg` from the event log, and calls `request_refund(deposit_msg, attacker_btc_address, tx_bytes, vout, proof, None)` with a valid Merkle proof.
4. `request_refund_callback` stores `attacker_btc_address` as `refund_address` for that UTXO key. Any subsequent `request_refund` by the legitimate user reverts with `"Refund request already exists for this UTXO"`.
5. After `unsafe_refund_timelock_sec` elapses (assuming the DAO/Operator does not call `reject_refund`), the attacker calls `execute_refund(utxo_storage_key, None)`.
6. `finalize_refund_with_psbt` builds a Bitcoin transaction paying `attacker_btc_address` the full deposit amount minus gas fee, and submits it to the MPC signing pipeline. The user's BTC is irrecoverably transferred to the attacker.

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L581-589)
```rust
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
