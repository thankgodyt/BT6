### Title
Excess `attached_deposit` Permanently Stuck on Bridge When Calling Refund Entry Points — (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
Both `internal_request_refund` and `resolve_execute_refund_timelock` enforce only a **minimum** attached-deposit check (`>=`). Any NEAR attached beyond the required storage amount is silently absorbed by the contract with no refund path, permanently locking user funds.

### Finding Description
The vulnerability class from the external report is: a payable function accepts native currency with only a lower-bound check, so any excess above the required amount is permanently stuck on the contract.

The direct analog exists in two places in `refund.rs`:

**Location 1 — `internal_request_refund`:**

```rust
require!(
    env::attached_deposit() >= self.required_balance_for_request_refund(),
    "Insufficient deposit for storage"
);
``` [1](#0-0) 

The check is `>=`, not `==`. No code after this point refunds the difference between `attached_deposit` and `required_balance_for_request_refund()`. The entire attached amount stays on the contract.

**Location 2 — `resolve_execute_refund_timelock`:**

```rust
require!(
    env::attached_deposit() >= self.required_balance_for_execute_refund(),
    "Insufficient deposit for storage"
);
``` [2](#0-1) 

Same pattern: minimum-only guard, no excess refund.

The inline comment in the same file notes that the required balance for a refund request is sized to cover approximately 2 NEAR of storage:

> "at this cap a request stores ~200 KB ≈ 2 NEAR, which `required_balance_for_request_refund` is sized to cover." [3](#0-2) 

A user who attaches 10 NEAR when only 2 NEAR is required will permanently lose 8 NEAR to the contract with no recovery path available to them.

### Impact Explanation
Any NEAR attached in excess of the required storage deposit is permanently locked inside the bridge contract. There is no user-callable function to reclaim it. The only possible recovery would require a privileged DAO action, which is not guaranteed and is outside the user's control. This matches the **Medium** impact class: *harmful smart-contract behavior without direct funds theft, including stuck bridge state requiring operator intervention*, and potentially **Critical** if a user attaches a large amount (e.g., mistakenly attaching their full wallet balance).

### Likelihood Explanation
The required storage deposit amount is not a round number and is not displayed to users in a standard way. Users calling `request_refund` or `execute_refund` must guess or compute the exact required amount. Over-attaching is a natural mistake, especially since the `>=` check silently accepts any larger value without warning. Any unprivileged NEAR account that has a refundable deposit can trigger this path.

### Recommendation
Replace the minimum-only guard with an exact check, or — more user-friendly — compute the excess after the storage deposit is consumed and explicitly refund it to `env::predecessor_account_id()`:

```rust
let required = self.required_balance_for_request_refund();
let attached = env::attached_deposit();
require!(attached >= required, "Insufficient deposit for storage");
let excess = attached.saturating_sub(required);
if excess > NearToken::from_yoctonear(0) {
    Promise::new(env::predecessor_account_id()).transfer(excess);
}
```

Apply the same fix to `resolve_execute_refund_timelock` for `required_balance_for_execute_refund`.

### Proof of Concept
1. User has a BTC deposit that failed to mint nBTC and wants a refund.
2. User calls the public `request_refund` entry point (which delegates to `internal_request_refund`) and attaches `10 NEAR` as deposit, not knowing the exact required amount (~2 NEAR).
3. The `>=` check at line 147 passes silently.
4. The refund request is stored; the contract retains all 10 NEAR.
5. The user has permanently lost ~8 NEAR with no user-callable recovery mechanism.
6. The same scenario applies to `execute_refund` via `resolve_execute_refund_timelock` at line 202. [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L17-26)
```rust
/// Upper bound on the deposit `tx_bytes` accepted by `request_refund`.
///
/// The RefundRequest stores `tx_bytes` verbatim (no truncation — `execute_refund`
/// later decodes them to rebuild the refund tx), so storage grows ~1:1 with tx size:
/// at this cap a request stores ~200 KB ≈ 2 NEAR, which `required_balance_for_request_refund`
/// is sized to cover. The cap also sits safely below the hard gas ceiling: decoding +
/// borsh-storing the tx happens in `request_refund_callback` (only 20 Tgas), which runs
/// out of gas around ~250 KB regardless of the attached deposit. 200 KB is ~1350 signed
/// P2PKH inputs — far above any real deposit (1-2 inputs), incl. large consolidations.
pub(crate) const MAX_REQUEST_REFUND_TX_BYTES: usize = 200_000;
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
