### Title
Publicly Callable `request_refund` Allows Attacker to Redirect User BTC Refunds to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary

`request_refund` and `execute_refund` carry no individual `#[trusted_relayer]` guard. Any NEAR account can submit a refund request for a victim's deposit UTXO, supplying an attacker-controlled BTC `refund_address`. After the `unsafe_refund_timelock_sec` elapses, the attacker calls `execute_refund` and the bridge MPC-signs a transaction that sends the victim's BTC to the attacker's address.

### Finding Description

The `#[trusted_relayer]` attribute on the outer `impl Contract` block in `bridge.rs` is a macro-configuration step, not a per-method gate. Individual methods that must be relayer-gated carry their own `#[trusted_relayer]` (e.g., `verify_deposit_v2`, `verify_withdraw_v2`, `verify_refund_finalize`). Methods without an individual attribute are publicly callable.

`request_refund` and `execute_refund` have no individual `#[trusted_relayer]`:

```
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn request_refund(...)   // line 510 – no #[trusted_relayer]

#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn execute_refund(...)   // line 582 – no #[trusted_relayer]
``` [1](#0-0) 

Inside `request_refund`, when `deposit_msg.refund_address` is `None`, the caller-supplied `refund_address` is stored verbatim with no ownership check:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

The `deposit_msg` is emitted publicly via `Event::LogDepositAddress` when `get_user_deposit_address` is called, and the BTC `tx_bytes` and inclusion proof are derivable from the public Bitcoin chain. An attacker therefore has all inputs needed to call `request_refund` for any victim deposit.

The `request_refund_callback` only checks that the UTXO has not already been finalized and that no duplicate request exists:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

Whichever caller lands first wins the slot. The victim's subsequent `request_refund` call reverts with "Refund request already exists for this UTXO."

`execute_refund` is also publicly callable after the timelock:

```rust
pub fn execute_refund(
    &mut self,
    utxo_storage_key: String,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
    let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
    self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
}
``` [4](#0-3) 

`resolve_execute_refund_timelock` only uses the `is_privileged` flag to shorten the timelock for pre-authorized addresses; it does not block unprivileged callers from executing after `unsafe_refund_timelock_sec`:

```rust
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [5](#0-4) 

The only mitigation is that DAO/Operator can call `reject_refund` within the timelock window. This is an operational control, not a code-level invariant.

### Impact Explanation

After the attacker's `request_refund` is stored with their BTC address and the `unsafe_refund_timelock_sec` elapses, `execute_refund` builds a PSBT spending the victim's deposit UTXO and routes it through the MPC signing pipeline. The resulting signed Bitcoin transaction pays the attacker's address. The victim's BTC is permanently lost. This is a direct theft of user funds from the bridge.

**Impact: Critical** — Significant loss of user funds via attacker-controlled redirection of the MPC-signed refund transaction.

### Likelihood Explanation

All inputs required to call `request_refund` are public:
- `deposit_msg` is emitted on-chain via `Event::LogDepositAddress`.
- `tx_bytes`, `vout`, and the inclusion proof are derivable from the public Bitcoin blockchain.

The attacker does not need to front-run in the traditional mempool sense; they can submit the malicious `request_refund` at any point after the Bitcoin deposit confirms and before the victim does. The only defense is DAO/Operator rejection within `unsafe_refund_timelock_sec`, which is an operational dependency. An attacker can time the submission to coincide with periods of low operator availability.

**Likelihood: Medium** — Requires the attacker to act before the victim and DAO/Operator to miss the rejection window, but all data is public and the attack is straightforward.

### Recommendation

1. **Bind `refund_address` to the caller**: In `request_refund`, when `deposit_msg.refund_address` is `None`, record `env::predecessor_account_id()` as the authorized requester and only allow that same account to call `execute_refund` for that request. This prevents a third party from hijacking the refund destination.

2. **Alternatively, require `deposit_msg.refund_address` to always be set**: Enforce that `deposit_msg.refund_address` is `Some(...)` at deposit time, so the refund destination is committed to on-chain before any refund request can be submitted. This eliminates the caller-supplied address path entirely.

3. **Add `#[trusted_relayer]` to `request_refund`**: Gate submission to whitelisted relayers, consistent with other sensitive bridge entry points.

### Proof of Concept

1. Alice deposits BTC to the bridge. Her `deposit_msg` has `refund_address: None`. The `Event::LogDepositAddress` event reveals her `deposit_msg` publicly.
2. The deposit is confirmed on Bitcoin. Alice's BTC is now held by the bridge UTXO.
3. Alice's deposit cannot be finalized (e.g., she used an unregistered `post_action`), so she intends to call `request_refund`.
4. Attacker Eve observes the `LogDepositAddress` event and the Bitcoin transaction. She constructs the same `deposit_msg`, `tx_bytes`, `vout`, and `proof`.
5. Eve calls `request_refund(deposit_msg, eve_btc_address, tx_bytes, vout, proof, None)` with the required NEAR storage deposit. The light-client verification passes. `request_refund_callback` stores a `RefundRequest` with `refund_address = eve_btc_address`.
6. Alice calls `request_refund(...)` with her own BTC address. It reverts: "Refund request already exists for this UTXO."
7. After `unsafe_refund_timelock_sec` elapses (and assuming DAO/Operator does not reject), Eve calls `execute_refund(utxo_storage_key, None)`.
8. The bridge builds a PSBT spending Alice's deposit UTXO, requests an MPC signature, and broadcasts a Bitcoin transaction paying `eve_btc_address`.
9. Alice's BTC is permanently redirected to Eve. [6](#0-5) [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-227)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L496-580)
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
```
