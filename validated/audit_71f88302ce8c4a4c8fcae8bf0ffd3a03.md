### Title
Unvalidated Refund Address Allows Theft of BTC from Contract-Initiated Deposits with No Pre-Authorized `refund_address` - (File: contracts/satoshi-bridge/src/refund.rs)

---

### Summary

When `deposit_msg.refund_address` is `None`, any unprivileged NEAR account can call `request_refund` and supply an arbitrary BTC address as the refund destination. There is no check that the caller owns or controls that address. For contract-initiated deposits (e.g., via `safe_deposit` / Omni Bridge) where no `refund_address` was embedded in the `deposit_msg`, an attacker can front-run or race the legitimate refund request and redirect the entire deposit UTXO to their own BTC address.

---

### Finding Description

In `internal_request_refund`, the only validation applied to the caller-supplied `refund_address` is a conditional equality check against `deposit_msg.refund_address`:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 154-158
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

When `deposit_msg.refund_address` is `None` (the `if let` arm is skipped entirely), the caller-provided `refund_address` is stored verbatim in the `RefundRequest` with zero ownership validation:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 564-574
let refund_request = RefundRequest {
    ...
    refund_address,   // ← attacker-controlled, no ownership check
    ...
};
``` [2](#0-1) 

Later, `internal_execute_refund` (Bitcoin path) builds the PSBT output directly from `refund_request.refund_address` without re-validating ownership:

```rust
// contracts/satoshi-bridge/src/bitcoin_utils/refund.rs  line 30
let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);
``` [3](#0-2) 

The `DepositMsg` struct shows that `refund_address` is an optional field — it is `None` by default:

```rust
// contracts/satoshi-bridge/src/deposit_msg.rs  lines 26-27
// BTC address for refund if deposit is never finalized.
pub refund_address: Option<String>,
``` [4](#0-3) 

Contract-initiated deposits (via `safe_deposit` / Omni Bridge) routinely omit `refund_address` because the depositing NEAR contract has no BTC address of its own — exactly the same class of caller that cannot control a BTC address, mirroring the L2-contract-cannot-control-L1-address problem in the reference report.

The only mitigation is a longer `unsafe_refund_timelock_sec` applied when `deposit_msg.refund_address` is `None`, giving the DAO/Operator a window to reject suspicious requests:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 223-227
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [5](#0-4) 

This is a trust-based, not cryptographic, mitigation. If the DAO/Operator misses the window, or if `unsafe_refund_timelock_sec` is configured to a short value, the attacker's request executes and the BTC is irreversibly sent to the attacker's address.

---

### Impact Explanation

**Critical — Significant theft of user or protocol funds.**

An attacker who successfully races or front-runs a legitimate refund request for a contract-initiated deposit with `deposit_msg.refund_address = None` causes the entire deposit UTXO (minus gas fee) to be signed by the MPC and broadcast to the attacker's BTC address. The loss is permanent and on-chain irreversible once the refund transaction is confirmed.

---

### Likelihood Explanation

**Medium.**

- Contract-initiated deposits (Omni Bridge / `safe_deposit`) are a documented and intended use case of the bridge.
- Such deposits routinely omit `deposit_msg.refund_address` because the NEAR contract has no BTC address.
- Failed or stuck `safe_deposit` flows (cross-contract call failures, relayer downtime) are explicitly anticipated by the refund system.
- `request_refund` is a public, permissionless function (no `#[access_control_any]` guard; the wiki states "Any user can initiate a refund by calling `request_refund`").
- The attacker only needs to monitor the bridge for unfinalized contract-initiated deposits and submit a `request_refund` before the legitimate party does, or before the DAO/Operator rejects it.
- The `unsafe_refund_timelock_sec` window is the only barrier, and its length is a configuration parameter that may be short.

---

### Recommendation

1. **Require a pre-authorized `refund_address`** in `deposit_msg` for any deposit whose `recipient_id` is a contract account (i.e., not an implicit/EOA account). Revert `request_refund` if `deposit_msg.refund_address` is `None` and the depositor is a contract, analogous to the fix applied in the reference report.
2. **Alternatively**, bind the `refund_address` to the NEAR predecessor at `request_refund` time by requiring the caller to sign a challenge proving BTC key ownership, or by restricting `request_refund` so that only the original `deposit_msg.recipient_id` (or a DAO/Operator) can submit a refund when no `refund_address` was pre-authorized.
3. At minimum, document clearly that any contract using `safe_deposit` **must** set `deposit_msg.refund_address` to a BTC address it controls, and enforce this at the contract level.

---

### Proof of Concept

1. Omni Bridge calls `verify_deposit_v2` with a `DepositMsg { recipient_id: "omni.near", refund_address: None, safe_deposit: Some(...), ... }`. The deposit is never finalized (e.g., the cross-contract call to Omni Bridge fails).

2. Attacker observes the unfinalized deposit on-chain (the `RefundRequested` event or the absence of a `DepositVerified` event for the UTXO).

3. Attacker calls `request_refund` with `refund_address = "attacker_btc_address"` and attaches the required NEAR storage deposit. Because `deposit_msg.refund_address` is `None`, the check at `refund.rs:154-158` is skipped and the attacker's address is stored.

4. After `unsafe_refund_timelock_sec` elapses (and assuming the DAO/Operator does not reject the request), the attacker calls `execute_refund`. The bridge builds a PSBT paying the full deposit UTXO (minus gas fee) to `"attacker_btc_address"` and submits it to the MPC for signing.

5. The MPC signs the transaction; the attacker broadcasts it. The BTC is permanently transferred to the attacker. The original depositor (Omni Bridge / its users) loses the funds with no recourse. [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L137-183)
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L223-227)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-574)
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
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L30-30)
```rust
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-27)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
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
