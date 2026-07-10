### Title
Any Unprivileged Caller Can Submit a Refund Request with an Attacker-Controlled BTC Address for Any Unverified Deposit — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` imposes no check that the caller is the original depositor. When `deposit_msg.refund_address` is `None`, the caller freely supplies any BTC address as the refund destination. An unprivileged attacker who observes a victim's BTC deposit on-chain can submit a refund request pointing to their own address and, after the `unsafe_refund_timelock_sec` window, execute the refund and receive the victim's BTC.

---

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` is a public, permissionless function (only paused by `PauseManager`/`DAO`):

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
``` [1](#0-0) 

Inside `request_refund_callback`, the only address-binding check is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case — it is an optional field), this branch is skipped entirely and the caller-supplied `refund_address` is stored verbatim: [3](#0-2) 

There is no check that `env::predecessor_account_id()` equals `deposit_msg.recipient_id` or any other depositor-identity assertion anywhere in the refund request path.

The `deposit_msg` used to derive the deposit address is passed as a parameter to the public view function `get_user_deposit_address`, making it observable from NEAR transaction history. An attacker can reconstruct it, obtain the BTC Merkle proof from the public Bitcoin blockchain, and call `request_refund` with their own BTC address.

After `unsafe_refund_timelock_sec` (default **14 days**) elapses, `execute_refund` is also permissionless: [4](#0-3) 

The timelock resolution confirms the longer window applies to caller-supplied addresses:

```rust
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [5](#0-4) 

The sole mitigation is manual DAO/Operator rejection via `reject_refund`. There is no automated or cryptographic binding of the refund address to the original depositor.

---

### Impact Explanation

If the DAO/Operator fails to reject the attacker's request within `unsafe_refund_timelock_sec`, the attacker calls `execute_refund`, which builds a PSBT spending the victim's deposit UTXO to the attacker's BTC address and submits it to the MPC signing pipeline. The victim's BTC is permanently redirected. This is a **significant loss of user funds** — the depositor receives neither nBTC (the UTXO is marked verified, blocking `verify_deposit`) nor their BTC back. [6](#0-5) 

---

### Likelihood Explanation

- `deposit_msg` is observable from NEAR transaction history (passed to the public `get_user_deposit_address` view call).
- The BTC transaction and its Merkle proof are public on the Bitcoin blockchain.
- The attacker only needs to attach a small NEAR storage deposit (`required_balance_for_request_refund`) to submit the request.
- The 14-day window is long but relies entirely on off-chain human monitoring; there is no on-chain enforcement binding the refund address to the depositor.
- Deposits that are slow to be relayed (e.g., during congestion or relayer downtime) are the highest-risk targets, as `verify_deposit` has not yet been called to block the refund path. [7](#0-6) 

---

### Recommendation

Bind the refund address to the depositor at request time. The simplest fix is to require that `env::predecessor_account_id()` matches `deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`. Alternatively, require that `deposit_msg.refund_address` is always set (non-`None`) so the refund destination is committed at deposit time and cannot be overridden by a third-party caller.

---

### Proof of Concept

1. Victim calls `get_user_deposit_address` with `deposit_msg = { recipient_id: "victim.near", refund_address: null, ... }` — observable on NEAR.
2. Victim sends BTC to the derived address; the transaction is confirmed on Bitcoin.
3. Attacker reconstructs `deposit_msg`, fetches `tx_bytes` and Merkle proof from Bitcoin.
4. Attacker calls:
   ```
   request_refund(
     deposit_msg = { recipient_id: "victim.near", refund_address: null, ... },
     refund_address = "attacker_btc_address",
     tx_bytes = <victim's tx>,
     vout = 0,
     proof = <valid merkle proof>,
     gas_fee = null
   )
   ```
   attaching the required NEAR storage deposit.
5. DAO/Operator does not notice or does not act within 14 days.
6. Attacker calls `execute_refund(utxo_storage_key)` — the MPC signs a transaction paying `attacker_btc_address`.
7. Victim's BTC is permanently lost; the UTXO is marked verified, blocking any future `verify_deposit` mint. [8](#0-7) [9](#0-8)

### Citations

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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-228)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-381)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

```

**File:** contracts/satoshi-bridge/src/refund.rs (L496-581)
```rust
    #[private]
    pub fn request_refund_callback(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        gas_fee: Option<u128>,
    ) -> bool {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");

        let config = self.internal_config();
        let transaction = crate::WrappedTransaction::decode(&tx_bytes.0, &config.chain)
            .expect("Deserialization tx_bytes failed");
        let output = &transaction.output()[vout];

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

        let amount = u128::from(output.value.to_sat());
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id,
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );

        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );

        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );

        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );

        Event::RefundRequested {
            deposit_msg: deposit_msg.clone(),
            utxo_storage_key: utxo_storage_key.clone(),
            amount: amount.into(),
            refund_address: refund_address.clone(),
            gas_fee: resolved_gas_fee.into(),
        }
        .emit();

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

        true
    }
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-28)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
