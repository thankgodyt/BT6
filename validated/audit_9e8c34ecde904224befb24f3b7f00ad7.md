### Title
Unauthorized Refund Redirection: Any Caller Can Hijack Unfinalized BTC Deposits via `request_refund` - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

The `request_refund` function imposes no caller-identity check. Any NEAR account can submit a refund request for any unfinalized BTC deposit and supply an arbitrary BTC `refund_address`. Because `deposit_msg` is publicly broadcast on-chain via `LogDepositAddress` events, an attacker can observe pending deposits, race to register a refund request pointing to their own BTC address, and — if the DAO/Operator fails to reject within the `unsafe_refund_timelock_sec` window — drain the victim's BTC.

---

### Finding Description

**Step 1 — `deposit_msg` is public.**
When a user calls `get_user_deposit_address`, the full `deposit_msg` (including `recipient_id`) is emitted on-chain: [1](#0-0) 

An attacker passively monitors these events to collect every `deposit_msg` in flight.

**Step 2 — `request_refund` has no caller authorization.**
The public entry point carries only a pause guard and an optional DAO/Operator check for the `gas_fee` parameter. There is no requirement that the caller be the `deposit_msg.recipient_id` or any party related to the deposit: [2](#0-1) 

**Step 3 — Attacker-supplied `refund_address` is accepted when `deposit_msg.refund_address` is `None`.**
The callback only enforces address consistency when the original `deposit_msg` already contained a `refund_address`. When it is `None` (the common case for standard deposits), the caller's arbitrary address is stored verbatim: [3](#0-2) 

**Step 4 — The only protection is a 14-day timelock and DAO discretion.**
For caller-supplied addresses the `unsafe_refund_timelock_sec` (default 14 days) is applied, explicitly to give DAO/Operator time to reject suspicious requests: [4](#0-3) [5](#0-4) 

If the DAO does not reject within that window, `execute_refund` is callable by anyone and the BTC is sent to the attacker's address.

**Step 5 — `execute_refund` is also permissionless.**
After the timelock elapses, any account can finalize the refund: [6](#0-5) 

---

### Impact Explanation

If the DAO/Operator fails to reject the malicious request within 14 days, the victim's BTC (the unfinalized deposit UTXO) is transferred to the attacker's BTC address. The bridge's `verified_deposit_utxo` set is then updated to block any subsequent legitimate `verify_deposit` for that UTXO, permanently preventing the victim from receiving nBTC. The victim loses both the BTC and the nBTC. This constitutes **significant theft and permanent loss of user funds**.

---

### Likelihood Explanation

- `deposit_msg` is publicly logged on-chain for every deposit; no off-chain secret is required.
- Standard deposits routinely omit `deposit_msg.refund_address` (it is `skip_serializing_if = "Option::is_none"`), making the majority of deposits vulnerable.
- The attacker only needs to pay the storage anti-spam deposit (`required_balance_for_request_refund`) and wait 14 days.
- DAO monitoring is a social/operational control, not a cryptographic guarantee; a single missed rejection is sufficient for the attack to succeed.
- The attack is silent and indistinguishable from a legitimate refund request until the DAO inspects the `refund_address`.

Likelihood: **Medium** (requires an unfinalized deposit window and DAO inaction, but the entry path is fully permissionless and the required information is public).

---

### Recommendation

1. **Bind `request_refund` to the deposit owner**: require `env::predecessor_account_id() == deposit_msg.recipient_id`, so only the intended nBTC recipient can initiate a refund for their own deposit.
2. **Alternatively, mandate `deposit_msg.refund_address` at deposit time**: reject `request_refund` calls where `deposit_msg.refund_address` is `None`, forcing users to pre-commit their BTC refund address before depositing. This eliminates the caller-supplied address path entirely.
3. As a defense-in-depth measure, emit a prominent on-chain alert event when a refund request is registered with a caller-supplied address, to aid DAO monitoring.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address(deposit_msg)` where `deposit_msg.refund_address = None`. The event `LogDepositAddress { deposit_msg, ... }` is emitted on-chain.
2. Alice sends BTC to the derived deposit address. The relayer has not yet called `verify_deposit`.
3. Attacker Bob observes the `LogDepositAddress` event, extracts Alice's `deposit_msg`, and calls:
   ```
   request_refund(
       deposit_msg = <Alice's deposit_msg>,
       refund_address = <Bob's BTC address>,
       tx_bytes = <Alice's BTC tx>,
       vout = <Alice's vout>,
       proof = <valid Merkle proof>,
       gas_fee = None,
   )
   ```
   Bob attaches the required storage deposit. The light-client proof passes; `request_refund_callback` stores the request with Bob's address.
4. The DAO does not notice or does not act within 14 days.
5. Bob (or anyone) calls `execute_refund(utxo_storage_key, None)`. The bridge builds a PSBT spending Alice's deposit UTXO and sends the BTC to Bob's address.
6. `verify_refund_finalize` is called after the BTC confirms. Alice's UTXO is marked in `verified_deposit_utxo`; any future `verify_deposit` for that UTXO is permanently blocked. Alice loses her BTC with no recourse.

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

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
