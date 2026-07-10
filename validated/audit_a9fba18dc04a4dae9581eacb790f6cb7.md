### Title
Caller-Controlled `gas_fee` in `request_refund` Has No Upper-Bound Validation, Enabling Refund Drain - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
Any unprivileged NEAR account can call `request_refund` and supply an arbitrarily large `gas_fee` (up to `deposit_amount - 1`). The contract stores this value verbatim and later deducts it from the user's refund output. Unlike the withdrawal path — which enforces `gas_fee ∈ [min_btc_gas_fee, max_btc_gas_fee]` — the refund path only checks `resolved_gas_fee < amount`, leaving no ceiling. A first-mover attacker can front-run a legitimate refund request, lock the UTXO with an inflated fee, and drain the user's deposit if the DAO fails to reject the request within the timelock.

### Finding Description

In `request_refund_callback`, the caller-supplied `gas_fee` is resolved and stored with only a single guard:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
``` [1](#0-0) 

This value is then persisted directly into `RefundRequest.gas_fee` and later used to compute the amount returned to the user:

```rust
let refund_amount = refund_request
    .amount
    .checked_sub(refund_request.gas_fee)
    .expect("Deposit amount too small to cover gas fee");
``` [2](#0-1) 

By contrast, the withdrawal PSBT validation enforces a strict two-sided bound:

```rust
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    ...
);
``` [3](#0-2) 

The refund path applies no equivalent upper-bound check against `config.max_btc_gas_fee`. [4](#0-3) 

Additionally, the `DepositMsg` struct has no field for the user to pre-commit a maximum acceptable refund gas fee, so the user has no on-chain mechanism to protect themselves:

```rust
pub struct DepositMsg {
    pub recipient_id: AccountId,
    pub post_actions: Option<Vec<PostAction>>,
    pub extra_msg: Option<String>,
    pub safe_deposit: Option<SafeDepositMsg>,
    pub refund_address: Option<String>,
    // no max_refund_gas_fee field
}
``` [5](#0-4) 

Once a refund request is stored, a duplicate for the same UTXO is rejected:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [6](#0-5) 

This means a front-running attacker who submits first with an inflated fee blocks the legitimate user from submitting their own request until the DAO explicitly rejects the malicious one.

### Impact Explanation

An attacker who submits `request_refund` with `gas_fee = deposit_amount - 1` causes `refund_amount = 1 satoshi`. The user's entire deposit is effectively destroyed as a "fee." This constitutes a significant, attacker-triggered loss of user funds. The DAO can reject the request during the timelock window (`refund_timelock_sec` / `unsafe_refund_timelock_sec`), but this is an operational safety net, not a protocol-level guarantee. If the DAO is slow or offline, `execute_refund` can be called after the timelock and the drain is finalized. [7](#0-6) 

**Matched allowed impact:** Medium — attacker-triggered temporary locking of bridged funds and potential significant loss of user funds without direct theft of protocol reserves.

### Likelihood Explanation

`internal_request_refund` has no role-based access control; any NEAR account can call it provided they attach the required storage deposit and supply a valid BTC inclusion proof. [8](#0-7)  The BTC transaction bytes and deposit message are public on-chain data, so an attacker can observe a pending refund and front-run it. The attack requires no privileged key, no operator collusion, and no off-chain capability beyond monitoring the NEAR mempool.

### Recommendation

1. **Enforce `max_btc_gas_fee` in the refund path**, mirroring the withdrawal validation:
   ```rust
   require!(
       resolved_gas_fee >= config.min_btc_gas_fee
           && resolved_gas_fee <= config.max_btc_gas_fee,
       "Refund gas fee out of valid range"
   );
   ```
2. **Allow users to embed a `max_refund_gas_fee` in `DepositMsg`** so the contract can reject any refund request whose fee exceeds the user's stated tolerance, analogous to how `max_gas_fee` is accepted in the withdrawal flow. [9](#0-8) 

### Proof of Concept

1. Alice deposits 1 000 000 satoshis to the bridge-controlled address with a `DepositMsg` that is never finalized.
2. Attacker observes the BTC transaction on-chain and calls `request_refund` with `gas_fee = 999_999` (one satoshi below the deposit amount). The only check — `999_999 < 1_000_000` — passes.
3. The `RefundRequest` is stored with `gas_fee = 999_999`. Alice cannot submit her own refund request (duplicate guard fires).
4. If the DAO does not call `reject_refund` before `unsafe_refund_timelock_sec` elapses, the attacker (or anyone) calls `execute_refund`.
5. `refund_amount = 1_000_000 - 999_999 = 1`. Alice receives 1 satoshi; 999 999 satoshis are consumed as "gas fee" and lost.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L201-228)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L280-283)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L544-547)
```rust
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L549-553)
```rust
        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L34-42)
```rust
        if let Some(max_gas_fee) = max_gas_fee {
            require!(
                gas_fee <= max_gas_fee.0,
                format!(
                    "Gas fee does not match the provided max fee (gas fee = {}; max gas fee = {})",
                    gas_fee, max_gas_fee.0
                )
            );
        }
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L252-258)
```rust
        require!(
            gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
            format!(
                "Invalid gas fee ({}). valid range: [{}, {}].",
                gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
            )
        );
```

**File:** contracts/satoshi-bridge/src/config.rs (L84-87)
```rust
    pub min_btc_gas_fee: u128,
    // The max gas fee applicable for Bitcoin transactions
    #[serde(with = "u128_dec_format")]
    pub max_btc_gas_fee: u128,
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L12-28)
```rust
pub struct DepositMsg {
    // The NEAR account receiving nBTC.
    pub recipient_id: AccountId,
    // Parameters for executing ft_transfer_call after successful nBTC minting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_actions: Option<Vec<PostAction>>,
    // Used to support other dApps extending based on verify_deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_msg: Option<String>,
    // Replacment for the legacy post_actions to support safer cross-contract calls.
    // If this field is present, the legacy post_actions field must be None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_deposit: Option<SafeDepositMsg>,
    // BTC address for refund if deposit is never finalized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```
