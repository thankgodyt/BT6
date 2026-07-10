### Title
Attacker-Controlled Refund Address Redirects Victim's BTC Refund Without Depositor Authorization — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

Any unprivileged NEAR account can call `request_refund` on a deposit whose `DepositMsg.refund_address` is `None`, supplying an arbitrary attacker-controlled BTC address as the refund destination. Because the `deposit_msg` is publicly visible on-chain and no check ties the caller to the original depositor, an attacker can front-run the legitimate refund request and redirect the victim's BTC to their own address. The only mitigation is operator rejection within `unsafe_refund_timelock_sec`, which is not guaranteed.

---

### Finding Description

The `internal_request_refund` function accepts a caller-supplied `refund_address` parameter. When `deposit_msg.refund_address` is `None`, the function imposes no restriction on who may call it or what BTC address they may specify: [1](#0-0) 

If the field is `None`, the caller's `refund_address` is passed through unchecked into `request_refund_callback`, stored verbatim in `RefundRequest.refund_address`, and later used by `build_refund_output` to construct the Bitcoin output that pays the refund: [2](#0-1) 

The `deposit_msg` is derived from the BTC transaction's on-chain data (the deposit address is computed as `sha256(json(deposit_msg))`), so it is fully public. There is no `env::predecessor_account_id()` check binding the refund caller to the original depositor anywhere in `internal_request_refund`: [3](#0-2) 

The only protection is a longer `unsafe_refund_timelock_sec` applied when `deposit_msg.refund_address` is `None`, giving the DAO/Operator time to call `internal_reject_refund`: [4](#0-3) 

This is an operator-dependent mitigation, not a protocol-level guarantee.

---

### Impact Explanation

If the operator fails to reject within `unsafe_refund_timelock_sec` (due to monitoring failure, downtime, or an overwhelmingly short timelock), the attacker calls `execute_refund` and the bridge's MPC-signed Bitcoin transaction pays the victim's BTC to the attacker's address. The victim's deposit is permanently lost. This maps to: **Medium — bypass of bridge policies / attacker-triggered redirection of bridged funds**, escalating to **Critical** if operator monitoring is unavailable.

---

### Likelihood Explanation

- The `deposit_msg` is reconstructible from the public BTC transaction (the deposit address is deterministically derived from it).
- No privileged role is required; any NEAR account can call `request_refund`.
- The attack window is any period between the BTC deposit confirmation and the legitimate refund request being submitted.
- Operator monitoring is an off-chain assumption with no on-chain enforcement.

---

### Recommendation

**Short term:** In `internal_request_refund`, when `deposit_msg.refund_address` is `None`, require that `env::predecessor_account_id()` matches `deposit_msg.recipient_id` (the NEAR account that was to receive nBTC). This ties the refund caller to the original depositor without breaking the existing flow for pre-authorized refund addresses.

**Long term:** Require that `DepositMsg.refund_address` always be set at deposit time (non-optional), eliminating the caller-supplied address path entirely. If a caller-supplied path must remain, add a cryptographic proof (e.g., a signature over the `refund_address` by the key controlling the deposit output) to bind the refund destination to the depositor.

---

### Proof of Concept

1. User deposits BTC to the bridge-derived address with a `DepositMsg` containing `refund_address: None` and `recipient_id: "alice.near"`.
2. The deposit is not finalized (relayer delay or light client lag).
3. Attacker observes the BTC transaction on-chain, reconstructs the `DepositMsg` JSON (it is the preimage of the deposit address path).
4. Attacker calls `request_refund(deposit_msg, refund_address="attacker_btc_addr", tx_bytes=..., vout=0, proof=...)`.
5. `internal_request_refund` passes the check at line 154–158 (since `deposit_msg.refund_address` is `None`) and stores `RefundRequest { refund_address: "attacker_btc_addr", ... }`. [5](#0-4) 

6. `unsafe_refund_timelock_sec` elapses without operator rejection.
7. Attacker calls `execute_refund`; `build_refund_output` constructs a Bitcoin output paying `attacker_btc_addr`. [2](#0-1) 

8. MPC signs and broadcasts the transaction. Alice's BTC is permanently sent to the attacker.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L137-184)
```rust
    pub(crate) fn internal_request_refund(
        &self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<u128>,
    ) -> Promise {
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }

        let transaction =
            crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
        let tx_id = transaction.compute_txid().to_string();

        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);

        self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
            confirmations,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_REQUEST_REFUND_CALLBACK)
                .request_refund_callback(deposit_msg, refund_address, tx_bytes, vout, gas_fee),
        )
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L222-228)
```rust
            }
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
