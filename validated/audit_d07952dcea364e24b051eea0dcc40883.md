### Title
Unauthenticated `request_refund` Allows Any Caller to Redirect Unfinalized User Deposits to an Attacker-Controlled BTC Address — (File: `contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` is a public, permissionless function that accepts a caller-supplied `refund_address` with no verification that the caller is the intended deposit recipient. When a deposit's `deposit_msg.refund_address` is `None`, any third party can submit a refund request for another user's unfinalized BTC deposit and redirect the funds to an attacker-controlled BTC address. This is a direct analog to the Connext M-09 vulnerability class: just as a malicious relayer could substitute their own router address because the check only verified self-consistency (router signed the hash) rather than sequencer authorization, here any caller can substitute their own BTC address because the contract only checks that the `deposit_msg` matches the on-chain UTXO — not that the caller is the authorized recipient.

---

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` is decorated with `#[payable]` and `#[pause]` but **not** `#[trusted_relayer]`: [1](#0-0) 

The function accepts a caller-supplied `refund_address` and passes it directly to `internal_request_refund`: [2](#0-1) 

Inside `internal_request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [3](#0-2) 

When `deposit_msg.refund_address` is `None` — the common case for users who did not pre-authorize a BTC return address — this branch is skipped entirely and **any** `refund_address` string is accepted without restriction. There is no check that `env::predecessor_account_id()` equals `deposit_msg.recipient_id`.

The `request_refund_callback` verifies only that the BTC transaction is on-chain and that the output script matches the deposit address derived from `deposit_msg`: [4](#0-3) 

It does not verify the identity of the caller. The stored `RefundRequest` records the attacker-supplied `refund_address`: [5](#0-4) 

After the `unsafe_refund_timelock_sec` elapses, `execute_refund` is also permissionless (no `#[trusted_relayer]`): [6](#0-5) 

The refund PSBT is built paying `refund_amount` to the stored `refund_address`: [7](#0-6) 

The `deposit_msg` is public: `get_user_deposit_address` emits a `LogDepositAddress` event containing the full `deposit_msg`, `path`, and derived address: [8](#0-7) 

---

### Impact Explanation

An attacker who observes a user's `deposit_msg` (from the `LogDepositAddress` event) and the corresponding unfinalized BTC deposit can submit a `request_refund` with their own BTC address as `refund_address`. If the DAO/Operator does not reject the request within `unsafe_refund_timelock_sec`, the MPC pipeline will sign and broadcast a Bitcoin transaction sending the user's BTC to the attacker's address. This constitutes **direct theft of user BTC funds** — a Critical impact under the allowed scope ("Significant loss, theft, destruction, or permanent locking of user or protocol funds").

---

### Likelihood Explanation

The `deposit_msg` is publicly observable from NEAR events. The BTC transaction and Merkle proof are publicly available on-chain. The attacker only needs to pay the storage deposit for the refund request. The sole mitigation is the `unsafe_refund_timelock_sec` window during which DAO/Operator can reject the request. If the DAO/Operator is not actively monitoring refund requests, or if the timelock is long enough that the attack is not noticed, the theft succeeds. This makes the likelihood **Medium**: the attack is straightforward and cheap to attempt, but requires the DAO/Operator to fail to act.

---

### Recommendation

Add a caller-identity check in `request_refund` (or `internal_request_refund`) that requires `env::predecessor_account_id() == deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`. Alternatively, restrict `request_refund` to trusted relayers (add `#[trusted_relayer]`) and require relayers to attest that the `refund_address` was provided by the deposit owner out-of-band. A third option is to require `deposit_msg.refund_address` to always be pre-set (non-`None`) so that the refund destination is committed at deposit time and cannot be overridden by a third party.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address` with `deposit_msg = {recipient_id: "alice.near", refund_address: null, ...}`. The contract emits `LogDepositAddress` containing the full `deposit_msg`.
2. Alice sends BTC to the derived deposit address. The relayer does not call `verify_deposit`.
3. Attacker reads Alice's `deposit_msg` from the `LogDepositAddress` event and the BTC transaction from the Bitcoin network.
4. Attacker calls `request_refund(deposit_msg=alice_deposit_msg, refund_address="attacker_btc_addr", tx_bytes=..., vout=0, proof=...)` with sufficient attached NEAR for storage.
5. `request_refund_callback` verifies the BTC transaction is on-chain and the output script matches the deposit address — both pass. The request is stored with `refund_address = "attacker_btc_addr"`.
6. After `unsafe_refund_timelock_sec` passes without DAO/Operator rejection, attacker (or anyone) calls `execute_refund(utxo_storage_key)`.
7. The MPC pipeline signs a Bitcoin transaction paying Alice's BTC to `"attacker_btc_addr"`. Alice's funds are stolen.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L516-526)
```rust
        // Verify that the output script matches the deposit address derived from deposit_msg
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_script_pubkey == output.script_pubkey,
            "Output script_pubkey does not match deposit address"
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
