### Title
Unprivileged Attacker Can Redirect Victim's BTC to Attacker's Address via `request_refund` When `deposit_msg.refund_address` Is `None` — (`contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` is a permissionless call with no caller-identity check. When the victim's `deposit_msg.refund_address` is `None`, the contract skips the address-match guard and stores whatever `refund_address` the caller supplies. An attacker who observes the victim's `deposit_msg` on-chain can front-run or race the victim, register their own BTC address as the refund destination, and — if the DAO does not reject the request within `unsafe_refund_timelock_sec` — permanently redirect the victim's BTC.

---

### Finding Description

**Entry point — `internal_request_refund` (`refund.rs:154-158`)**

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

The guard is inside an `if let Some(...)` block. When `deposit_msg.refund_address` is `None` the entire check is skipped; the caller-supplied `refund_address` is forwarded to the callback without any validation. [1](#0-0) 

**Callback — `request_refund_callback` (`refund.rs:517-525`)**

The callback verifies that the BTC output's `script_pubkey` matches the deposit address derived from `deposit_msg`. This check passes as long as the attacker supplies the correct `deposit_msg` (which is public — it was emitted as a NEAR event when the victim called `get_user_deposit_address`). There is no check that the caller is the original depositor. [2](#0-1) 

The attacker-controlled `refund_address` is then stored verbatim in `RefundRequest.refund_address`: [3](#0-2) 

**Timelock branch — `resolve_execute_refund_timelock` (`refund.rs:216-227`)**

When `deposit_msg.refund_address` is `None`, the code selects `unsafe_refund_timelock_sec` — a longer timelock intended to give the DAO time to reject suspicious requests. This is the **only** protection against the attack. [4](#0-3) 

**`execute_refund` — no additional authorization (`bridge.rs:582-588`)**

`execute_refund` is also permissionless; any account can call it after the timelock elapses. The refund output is built directly from `refund_request.refund_address` — the attacker's address. [5](#0-4) 

---

### Impact Explanation

If the DAO does not reject the request within `unsafe_refund_timelock_sec`, the attacker calls `execute_refund`, the MPC signs a PSBT paying the attacker's BTC address, and the victim's BTC is permanently redirected. There is no recovery path once the signed transaction is broadcast. This is a direct, permanent loss of user funds.

---

### Likelihood Explanation

- `deposit_msg` is fully public (emitted via `LogDepositAddress` event on `get_user_deposit_address`).
- `request_refund` is permissionless — no NEAR account restriction.
- The attack window is any time between the victim's BTC confirmation and the victim calling `request_refund` themselves (or the relayer calling `verify_deposit`).
- The sole mitigation is the DAO rejecting the request within `unsafe_refund_timelock_sec`. If the DAO is offline, slow, or the timelock is misconfigured, the attack succeeds.
- The attacker only needs ~2 NEAR for the storage deposit, which is returned on success.

---

### Recommendation

Bind the refund address to the depositor at deposit time or enforce caller identity at `request_refund` time:

1. **Preferred**: Require `deposit_msg.refund_address` to always be set (non-`None`). Remove the `None` branch entirely, or treat a missing refund address as a protocol error.
2. **Alternative**: If `deposit_msg.refund_address` is `None`, require the caller of `request_refund` to be `deposit_msg.recipient_id` (the NEAR account that originally created the deposit), so only the intended recipient can supply a refund address.
3. **Defense-in-depth**: Emit a prominent on-chain event and require an explicit DAO approval (not just a rejection window) before `execute_refund` is allowed when `deposit_msg.refund_address` is `None`.

---

### Proof of Concept

```
1. Victim calls get_user_deposit_address({recipient_id: "victim.near", refund_address: None})
   → deposit address D emitted in LogDepositAddress event (public)

2. Victim sends 1 BTC to D; tx confirmed on Bitcoin.

3. Attacker observes victim's deposit_msg from NEAR event log.

4. Attacker calls request_refund(
       deposit_msg = {recipient_id: "victim.near", refund_address: None},
       refund_address = "attacker_btc_address",
       tx_bytes = <victim's BTC tx>,
       vout = 0,
       proof = <valid merkle proof>,
       attached_deposit = required_balance_for_request_refund()
   )
   → Light client verifies tx inclusion → passes
   → script_pubkey check passes (correct deposit_msg used)
   → RefundRequest stored with refund_address = "attacker_btc_address"

5. DAO does not reject within unsafe_refund_timelock_sec.

6. Attacker calls execute_refund(utxo_storage_key)
   → timelock elapsed → passes
   → PSBT built with output to "attacker_btc_address"
   → MPC signs → attacker broadcasts → victim's BTC permanently gone
```

The invariant that "a deposit UTXO must only be refunded to an address authorized by the original depositor" is violated because there is no on-chain binding between the depositor identity and the refund address when `deposit_msg.refund_address` is `None`. [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L133-135)
```rust
    /// Submit a refund request. Verifies the BTC transaction via Light Client first.
    /// If `deposit_msg.refund_address` is set, it must match the provided `refund_address`.
    /// If `deposit_msg.refund_address` is None, the provided `refund_address` is used.
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

**File:** contracts/satoshi-bridge/src/refund.rs (L216-227)
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
