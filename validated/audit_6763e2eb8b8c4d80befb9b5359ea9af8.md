### Title
Permissionless `request_refund()` Allows Any Caller to Redirect Unfinalized BTC Deposits to an Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`request_refund()` imposes no caller-identity check. When a deposit's `DepositMsg.refund_address` field is `None`, any unprivileged NEAR account can submit a refund request for any unfinalized BTC deposit and supply an arbitrary attacker-controlled BTC address as the `refund_address`. After the `unsafe_refund_timelock_sec` window elapses, the same (or any other) account can call the equally permissionless `execute_refund()`, causing the bridge's MPC to sign and broadcast a Bitcoin transaction that sends the deposited BTC to the attacker's address instead of the original depositor's.

### Finding Description

`request_refund()` is decorated only with `#[pause]` and `#[payable]` — there is no `#[access_control_any]` guard and no check that `env::predecessor_account_id()` matches the original depositor. [1](#0-0) 

Inside `internal_request_refund()`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case for standard deposits — `DepositMsg.refund_address` is an optional field), the branch is skipped entirely and the caller-supplied `refund_address` is stored verbatim in the `RefundRequest`. [3](#0-2) 

The stored `refund_address` is later used unconditionally in `internal_execute_refund()` to build the PSBT output:

```rust
let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);
``` [4](#0-3) 

`execute_refund()` is also permissionless — it carries no role guard — so after the timelock the attacker (or anyone) can trigger MPC signing: [5](#0-4) 

The only mitigation is `unsafe_refund_timelock_sec`, which is explicitly described as giving the DAO/Operator time to call `reject_refund()`. This is a governance-dependent, off-chain intervention, not a cryptographic guarantee. [6](#0-5) 

### Impact Explanation

An attacker who observes an unfinalized BTC deposit (one where `verify_deposit` was never called and `deposit_msg.refund_address` is `None`) can:

1. Call `request_refund()` with the correct `deposit_msg` (publicly derivable from the deposit address) and their own BTC address as `refund_address`.
2. Wait for `unsafe_refund_timelock_sec` to elapse.
3. Call `execute_refund()` to trigger MPC signing of a transaction paying the deposited BTC to the attacker's address.

The depositor's BTC is permanently lost. This matches **Critical — Significant loss or theft of user funds**.

### Likelihood Explanation

The attack is realistic under the following conditions, all of which occur in practice:

- **Relayer delay or failure**: The bridge's deposit flow depends on a relayer calling `verify_deposit`. Relayer downtime, mempool congestion, or a targeted DoS against the relayer creates a window.
- **`refund_address: None` deposits**: Standard (non-Omni) deposits commonly omit `refund_address` in `DepositMsg`, as it is an optional field.
- **DAO/Operator inaction**: The `unsafe_refund_timelock_sec` window requires active monitoring and timely `reject_refund()` calls. A sufficiently short timelock, an inattentive operator, or a coordinated attack that overwhelms the rejection pipeline removes this mitigation.

All deposit transactions are publicly visible on Bitcoin, so an attacker can monitor the chain for eligible targets with no privileged access.

### Recommendation

Require that the caller of `request_refund()` is either:
- The `recipient_id` named in `deposit_msg` (the intended nBTC receiver), or
- A trusted relayer / DAO / Operator role.

Alternatively, when `deposit_msg.refund_address` is `None`, disallow third-party refund requests entirely and require the depositor to re-submit with a `refund_address` embedded in the `deposit_msg` (the "pre-authorized" path), which already benefits from the shorter `refund_timelock_sec` and is protected by the address-match check.

### Proof of Concept

1. Alice sends 1 BTC to the bridge deposit address derived from `DepositMsg { recipient_id: "alice.near", refund_address: None, ... }`.
2. The relayer is temporarily offline; `verify_deposit` is never called.
3. Attacker Eve observes the BTC transaction on-chain, reconstructs the `deposit_msg` (the deposit address is deterministic and publicly logged via `Event::LogDepositAddress`), and calls:
   ```
   request_refund(
       deposit_msg = { recipient_id: "alice.near", refund_address: None, ... },
       refund_address = "eve_btc_address",
       tx_bytes = <alice's deposit tx>,
       vout = 0,
       proof = <merkle proof>,
       gas_fee = None
   )
   ```
   This succeeds because there is no caller check and `deposit_msg.refund_address` is `None`. [2](#0-1) 
4. The DAO/Operator fails to call `reject_refund()` before `unsafe_refund_timelock_sec` elapses.
5. Eve calls `execute_refund(utxo_storage_key)`. The bridge builds a PSBT paying 1 BTC (minus gas) to `eve_btc_address` and requests an MPC signature. [7](#0-6) 
6. Eve broadcasts the signed transaction. Alice's 1 BTC is permanently redirected to Eve.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-228)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-28)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L18-43)
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
```
