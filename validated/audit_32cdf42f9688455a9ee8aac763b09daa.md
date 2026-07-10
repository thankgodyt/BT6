### Title
Attacker Can Redirect Victim's Refund BTC to Arbitrary Address via Permissionless `request_refund` - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary

The `request_refund` function is publicly callable with no check that the caller is the original depositor. Because the `deposit_msg` is fully public (emitted on-chain as a `LogDepositAddress` event), an attacker can submit a refund request for a victim's unfinalized deposit while supplying the attacker's own BTC address as `refund_address`. After the `unsafe_refund_timelock_sec` elapses, the attacker can execute the refund and redirect the victim's BTC to themselves.

### Finding Description

`request_refund` accepts a caller-supplied `refund_address` with no restriction on who the caller is: [1](#0-0) 

There is no check that `env::predecessor_account_id()` equals `deposit_msg.recipient_id`. The only guard on `refund_address` is that it must match `deposit_msg.refund_address` **when that field is `Some`**: [2](#0-1) 

For standard deposits where `deposit_msg.refund_address` is `None` (the common case — the field is `skip_serializing_if = "Option::is_none"`), any caller can supply any BTC address: [3](#0-2) 

The `deposit_msg` used to derive the deposit address is emitted publicly as a `LogDepositAddress` event every time `get_user_deposit_address` is called: [4](#0-3) 

This means an attacker can reconstruct the exact `deposit_msg` for any victim's deposit from on-chain events, then call `request_refund` with the victim's `deposit_msg` and the attacker's own BTC address.

In `request_refund_callback`, the contract verifies the output script matches the deposit address derived from `deposit_msg` — but this only proves the BTC went to the correct deposit address, not that the caller is the rightful owner: [5](#0-4) 

### Impact Explanation

If a deposit is never finalized via `verify_deposit` (the exact scenario the refund system is designed for), an attacker who submitted a malicious `request_refund` can call `execute_refund` after `unsafe_refund_timelock_sec` and redirect the victim's BTC to their own address. The victim's BTC is permanently stolen. This is a direct theft of user funds — **Critical**.

### Likelihood Explanation

The attack is realistic in the primary failure scenario the refund system targets: a relayer outage or stuck deposit. The attacker's entry path is fully permissionless — no special role, no leaked key. The `deposit_msg` is public on-chain. The only mitigation is DAO/Operator rejection during the `unsafe_refund_timelock_sec` window: [6](#0-5) 

But DAO monitoring is not guaranteed, especially during the same outage that caused the deposit to go unfinalized. The attacker can also submit many such requests to overwhelm the rejection queue.

### Recommendation

Add a caller-identity check in `request_refund` (or its callback) requiring `env::predecessor_account_id() == deposit_msg.recipient_id`. This mirrors the recommended fix in H-04: bind the refund requester to the intended beneficiary rather than allowing arbitrary callers to supply a `refund_address` for someone else's deposit.

Alternatively, require that `deposit_msg.refund_address` is always `Some` and pre-committed at deposit-address-generation time, so the refund destination is locked into the deposit address derivation path and cannot be overridden by a third party.

### Proof of Concept

1. Alice calls `get_user_deposit_address(deposit_msg)` where `deposit_msg.refund_address = None`. The contract emits `LogDepositAddress { deposit_msg, path, deposit_address }`.
2. Alice sends BTC to the returned deposit address.
3. The relayer goes offline; `verify_deposit` is never called.
4. Attacker reads Alice's `deposit_msg` from the `LogDepositAddress` event.
5. Attacker calls `request_refund(deposit_msg=Alice's, refund_address=attacker_btc_addr, tx_bytes=..., vout=..., proof=...)` with sufficient attached NEAR for storage.
6. `request_refund_callback` verifies the BTC transaction is real and the output script matches Alice's deposit address — both pass. The refund request is stored with `refund_address = attacker_btc_addr`.
7. After `unsafe_refund_timelock_sec` elapses (and assuming DAO does not reject), attacker calls `execute_refund(utxo_storage_key)`.
8. The bridge builds a PSBT paying Alice's BTC to `attacker_btc_addr` and requests an MPC signature. Alice's BTC is sent to the attacker. [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L216-228)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L517-525)
```rust
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-28)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```

**File:** contracts/satoshi-bridge/src/event.rs (L71-75)
```rust
    LogDepositAddress {
        deposit_msg: DepositMsg,
        path: String,
        deposit_address: String,
    },
```
