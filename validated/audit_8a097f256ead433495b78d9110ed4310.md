### Title
Arbitrary Refund Address Redirection When `deposit_msg.refund_address` Is `None` - (File: `contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary

When a user deposits BTC using a `DepositMsg` with `refund_address: None`, any unprivileged NEAR account can call `request_refund` and supply an attacker-controlled BTC address as the `refund_address`. Because the contract only validates `refund_address` against `deposit_msg.refund_address` when the latter is `Some`, there is no binding between the refund destination and the original depositor. After the `unsafe_refund_timelock_sec` elapses without DAO/Operator intervention, the attacker calls `execute_refund` and the bridge's MPC pipeline sends the deposited BTC to the attacker's address.

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` is not decorated with `#[trusted_relayer]` on the function itself. The `#[trusted_relayer]` on the enclosing `impl` block at line 480 is the plugin-configuration attribute (analogous to the parameterized form in `lib.rs` lines 175-179); per-function enforcement requires the attribute on the function. Every other function in the same block that actually enforces the relayer check carries its own `#[trusted_relayer]` (e.g., `verify_deposit`, `verify_withdraw_v2`, `verify_refund_finalize`). `request_refund` carries only `#[payable]` and `#[pause(...)]`, making it callable by any NEAR account.

Inside `internal_request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

When `deposit_msg.refund_address` is `None` the branch is skipped entirely and the caller-supplied `refund_address` is stored verbatim in the `RefundRequest`:

```rust
let refund_request = RefundRequest {
    ...
    refund_address,   // ← attacker-controlled
    ...
};
``` [2](#0-1) 

`execute_refund` later builds the PSBT output directly from `refund_request.refund_address`:

```rust
let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);
``` [3](#0-2) 

and the MPC pipeline signs and broadcasts a transaction paying that address. The code itself acknowledges the risk and applies a longer `unsafe_refund_timelock_sec` as a mitigation:

```rust
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [4](#0-3) 

This is a trust-based mitigation, not a cryptographic one. If the DAO/Operator does not notice or does not act before the timelock expires, the attacker calls `execute_refund` and the BTC is irreversibly sent to the attacker's address.

### Impact Explanation

The attacker receives the victim's deposited BTC. The bridge's MPC signing is irreversible once the transaction is broadcast and confirmed. The victim's deposit is permanently lost. This matches **Critical: Significant loss, theft, destruction, or permanent locking of user or protocol funds.**

### Likelihood Explanation

**Medium.** The attack requires:
1. Observing a BTC deposit to a bridge address derived from a `DepositMsg` with `refund_address: None` (all `DepositMsg` fields are public).
2. Calling `request_refund` before the victim does (front-run on NEAR, which has deterministic block ordering and a public mempool).
3. Waiting for `unsafe_refund_timelock_sec` without the DAO/Operator rejecting the request.

The storage deposit anti-spam fee is small. The `deposit_msg` is fully reconstructible from on-chain events (`LogDepositAddress`). The DAO/Operator monitoring is an operational control, not a protocol guarantee.

### Recommendation

Bind the `refund_address` to the original depositor at deposit time or at request time:

- **Preferred**: Require that `deposit_msg.refund_address` is always `Some` (i.e., users must pre-authorize a BTC refund address when generating their deposit address). Reject `request_refund` calls where `deposit_msg.refund_address` is `None`.
- **Alternative**: Restrict `request_refund` to the NEAR account that is the `deposit_msg.recipient_id`, so only the intended nBTC recipient can initiate a refund.
- **Minimum**: Add `#[trusted_relayer]` to `request_refund` so that only whitelisted relayers can submit refund requests, and rely on the existing `unsafe_refund_timelock_sec` + DAO rejection as a second layer.

### Proof of Concept

1. Alice calls `get_user_deposit_address(DepositMsg { recipient_id: "alice.near", refund_address: None, ... })` and sends 100 000 sat to the returned address. The `LogDepositAddress` event is emitted on-chain.
2. The relayer never calls `verify_deposit` (e.g., the deposit is below the relayer's threshold).
3. Attacker reconstructs `deposit_msg` from the event, obtains `tx_bytes` and `proof` from the Bitcoin network, and calls:
   ```
   request_refund(
       deposit_msg,
       "attacker_btc_address",
       tx_bytes, vout, proof, None
   )
   ```
   The call succeeds because `deposit_msg.refund_address` is `None` — no validation of `"attacker_btc_address"` occurs.
4. DAO/Operator does not notice the request within `unsafe_refund_timelock_sec`.
5. Attacker calls `execute_refund(utxo_storage_key, None)`. The bridge builds a PSBT paying `"attacker_btc_address"` and initiates MPC signing.
6. Attacker (or anyone) calls `sign_btc_transaction`, broadcasts the signed transaction. Alice's 100 000 sat (minus gas fee) arrive at the attacker's address.
7. Attacker calls `verify_refund_finalize`; the refund request is cleaned up. Alice has no recourse. [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-183)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L201-227)
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
