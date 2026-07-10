### Title
Unprivileged Caller Can Front-Run `request_refund` to Redirect Victim's BTC Refund to Attacker-Controlled Address — (`File: contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` is callable by any unprivileged NEAR account with no ownership check on the deposit UTXO. When a victim's `deposit_msg.refund_address` is `None`, an attacker can front-run the victim's `request_refund` call and supply their own BTC address as `refund_address`. Because a duplicate-request guard then blocks the victim from filing a second request for the same UTXO, the victim is locked out of the refund flow and their BTC is directed to the attacker after the timelock expires.

---

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` (lines 510–535) carries only `#[payable]` and `#[pause]` guards — no `#[trusted_relayer]` attribute and no check that the caller is the owner of the deposit: [1](#0-0) 

Inside `internal_request_refund` (`contracts/satoshi-bridge/src/refund.rs`, lines 137–184), the only constraint on `refund_address` is that it must equal `deposit_msg.refund_address` **when that field is `Some`**: [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case — the field is optional and skipped during serialization), the caller-supplied `refund_address` is accepted verbatim and stored in the `RefundRequest`: [3](#0-2) [4](#0-3) 

In `request_refund_callback`, a duplicate-request guard then permanently blocks any second request for the same UTXO: [5](#0-4) 

After `unsafe_refund_timelock_sec` elapses, `execute_refund` is also callable by anyone (no `#[trusted_relayer]` on the function), and it pays out to the stored `refund_address` — the attacker's address: [6](#0-5) 

The timelock branch for the `refund_address = None` case uses `unsafe_refund_timelock_sec` (the *longer* timelock) specifically to give DAO/Operator time to reject, but rejection is not guaranteed: [7](#0-6) 

---

### Impact Explanation

If the DAO/Operator does not reject the malicious request within `unsafe_refund_timelock_sec`:

- `execute_refund` is called (by anyone, including the attacker) and the bridge's MPC pipeline constructs and signs a Bitcoin transaction paying the attacker's BTC address.
- The victim's BTC is permanently transferred to the attacker.
- The victim cannot file a competing refund request (duplicate guard) and has no self-service cancellation path.

Even if the DAO/Operator does reject in time, the victim's refund is temporarily blocked for the full `unsafe_refund_timelock_sec` window — a guaranteed griefing outcome.

**Impact: Critical (theft of user BTC) / Medium (temporary locking of bridged funds)**

---

### Likelihood Explanation

All inputs needed for the attack are public:

- The `deposit_msg` is derived deterministically from the deposit address, which is on-chain.
- The BTC transaction (`tx_bytes`, `vout`, Merkle proof) is visible on the Bitcoin blockchain.
- NEAR transactions are observable before finality, enabling front-running.

The attacker only needs to pay the NEAR storage deposit (`required_balance_for_request_refund`) and submit a valid Merkle proof — both are trivially achievable by any unprivileged account. The attack is most effective when the DAO/Operator is offline or slow to respond.

**Likelihood: Medium** (requires observing victim's pending `request_refund` call or knowing the UTXO, plus timing the DAO/Operator's unavailability).

---

### Recommendation

1. **Bind the refund request to the caller**: Record `env::predecessor_account_id()` as the `requester` in `RefundRequest` and require that only the requester (or DAO/Operator) can call `execute_refund` for that request.
2. **Alternatively, require `deposit_msg.refund_address` to be pre-set**: Reject `request_refund` calls where `deposit_msg.refund_address` is `None`, forcing users to embed their BTC address in the deposit message before the BTC transaction is broadcast. This eliminates the caller-supplied address vector entirely.
3. **Add a caller-ownership check**: At minimum, verify that the NEAR account calling `request_refund` matches `deposit_msg.recipient_id`, since that is the intended beneficiary of the deposit.

---

### Proof of Concept

1. **Victim** sends BTC to a deposit address derived from `deposit_msg = { recipient_id: "victim.near", refund_address: None, ... }`. The deposit is never finalized by a relayer.
2. **Victim** prepares a `request_refund` call with `refund_address = "victim_btc_address"`.
3. **Attacker** observes the victim's pending NEAR transaction (or independently discovers the UTXO on Bitcoin) and submits `request_refund` first with the same `deposit_msg` but `refund_address = "attacker_btc_address"`.
4. Attacker's `request_refund_callback` succeeds: `deposit_msg.refund_address` is `None` so no address-match check fires; the duplicate guard is not yet triggered; `RefundRequest { refund_address: "attacker_btc_address", created_at_sec: now, ... }` is stored.
5. Victim's `request_refund` call fails: `"Refund request already exists for this UTXO"`.
6. After `unsafe_refund_timelock_sec` (assuming DAO/Operator does not reject), attacker calls `execute_refund`. The bridge constructs a Bitcoin transaction paying `"attacker_btc_address"` and submits it to the MPC signing pipeline.
7. Victim's BTC is transferred to the attacker.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-27)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
```
