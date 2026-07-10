### Title
Attacker Can Pre-Register a Refund Request with a Malicious `refund_address` to Steal Unfinalized BTC Deposits — (File: `contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` is a permissionless function that allows any caller to register a refund request for a BTC deposit that was never finalized. When `deposit_msg.refund_address` is `None`, the caller freely supplies any `refund_address`. The first request for a given UTXO wins; duplicates are rejected. Because the `deposit_msg` is publicly emitted in the `LogDepositAddress` event, an attacker can observe it, submit `request_refund` before the legitimate user with their own `refund_address`, and — after the `unsafe_refund_timelock_sec` elapses — call `execute_refund` to redirect the BTC to themselves.

---

### Finding Description

**Step 1 — `deposit_msg` is public.**
`get_user_deposit_address` emits a `LogDepositAddress` event that includes the full `deposit_msg`: [1](#0-0) 

Any observer can reconstruct the exact `deposit_msg` from on-chain event logs.

**Step 2 — `request_refund` is permissionless and accepts any `refund_address` when `deposit_msg.refund_address` is `None`.** [2](#0-1) 

When the optional `refund_address` field is absent from the `deposit_msg`, the check is skipped entirely, and the caller-supplied `refund_address` is stored verbatim.

**Step 3 — First request wins; duplicates are rejected.**
In `request_refund_callback`, after light-client verification succeeds, the contract inserts the request and rejects any subsequent attempt for the same UTXO: [3](#0-2) 

An attacker who submits `request_refund` first — with the legitimate `deposit_msg` but their own `refund_address` — permanently occupies the slot. The legitimate user's subsequent call reverts.

**Step 4 — After `unsafe_refund_timelock_sec`, anyone can call `execute_refund`.** [4](#0-3) [5](#0-4) 

Because `deposit_msg.refund_address` is `None`, the longer `unsafe_refund_timelock_sec` applies. Once it elapses, the attacker calls `execute_refund`, which builds a Bitcoin transaction paying `refund_address` (the attacker's address) and routes it through the MPC signing pipeline.

**Step 5 — The refund UTXO is marked verified, permanently blocking the legitimate deposit.** [6](#0-5) 

After `execute_refund`, the UTXO is inserted into `verified_deposit_utxo`, so `verify_deposit` for the same UTXO will also be blocked.

---

### Impact Explanation

**Critical — Significant theft of user funds.** A user who sent BTC to a bridge deposit address (with no `refund_address` in their `deposit_msg`) and whose deposit was never finalized loses their BTC entirely. The attacker receives the full deposit amount minus the gas fee. The legitimate user cannot recover via `verify_deposit` (UTXO is marked verified) or via a new `request_refund` (slot is occupied, then removed after attacker's refund finalizes).

---

### Likelihood Explanation

**Medium.** The preconditions are:
1. The user called `get_user_deposit_address` (making `deposit_msg` public via event), or the attacker observes the `deposit_msg` from the user's own `request_refund` transaction before it is processed.
2. The user's deposit was never finalized (e.g., relayer failure, user error).
3. The user did not set `deposit_msg.refund_address`.
4. The DAO/Operator does not reject the malicious request within `unsafe_refund_timelock_sec`.

Conditions 1–3 are common in practice. Condition 4 is the only protocol-level mitigation, and it relies entirely on active operator monitoring — if the operator is offline or slow, the attack succeeds unconditionally.

---

### Recommendation

1. **Require `deposit_msg.refund_address` to be set** for permissionless `request_refund` calls. If it is `None`, restrict the call to the `recipient_id` specified in `deposit_msg` (i.e., only the intended nBTC recipient can initiate a refund without a pre-authorized address).
2. Alternatively, bind the `refund_address` to the caller's identity (e.g., require the caller to sign a message proving ownership of the BTC address).
3. Do not rely solely on the DAO/Operator rejection window as the primary defense against fund theft.

---

### Proof of Concept

```
1. Alice calls get_user_deposit_address(deposit_msg) where deposit_msg.refund_address = None.
   → LogDepositAddress event emitted with full deposit_msg.

2. Alice sends 1 BTC to the derived deposit address on Bitcoin.
   The relayer fails; verify_deposit is never called.

3. Attacker observes deposit_msg from the event log and the BTC tx on Bitcoin.

4. Attacker calls request_refund(deposit_msg, attacker_btc_address, tx_bytes, vout, proof, None)
   with attached NEAR storage deposit.
   → Light client verifies the BTC tx.
   → request_refund_callback stores RefundRequest { refund_address: attacker_btc_address, ... }.

5. Alice calls request_refund(..., alice_btc_address, ...).
   → Reverts: "Refund request already exists for this UTXO".

6. After unsafe_refund_timelock_sec elapses, attacker calls execute_refund(utxo_storage_key, None).
   → Bridge builds a BTC tx paying attacker_btc_address the full deposit minus gas fee.
   → MPC signs and broadcasts the tx.
   → Alice's 1 BTC is sent to the attacker.
   → verified_deposit_utxo is updated; Alice cannot recover via verify_deposit.
```

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L582-589)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L222-228)
```rust
            }
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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```
