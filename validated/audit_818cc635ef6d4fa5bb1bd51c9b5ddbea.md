### Title
First-Caller-Wins Refund Request Allows Attacker to Redirect BTC Refund Address and Block Legitimate Refund - (File: contracts/satoshi-bridge/src/api/bridge.rs, contracts/satoshi-bridge/src/refund.rs)

### Summary
`request_refund` is a public function callable by any NEAR account. It enforces a strict one-request-per-UTXO constraint. When a deposit's `deposit_msg.refund_address` is `None` (the common case), the caller freely supplies the BTC `refund_address`. An attacker who front-runs the legitimate user can register their own BTC address as the refund destination, permanently blocking the user from creating a valid refund request for that UTXO and, if the DAO fails to reject within the 14-day timelock, stealing the deposited BTC.

### Finding Description
`request_refund` in `bridge.rs` is decorated only with `#[payable]` and `#[pause(...)]` — it carries no `#[trusted_relayer]` guard at the function level, unlike `verify_deposit_v2` which has both the impl-block and function-level attribute. Any NEAR account may call it. [1](#0-0) 

Inside the async callback `request_refund_callback`, the contract enforces a hard uniqueness constraint: [2](#0-1) 

When `deposit_msg.refund_address` is `None`, the caller-supplied `refund_address` is accepted without any ownership check: [3](#0-2) 

The stored `refund_address` is later used verbatim when `execute_refund` builds the refund output: [4](#0-3) 

`execute_refund` is also public with no ownership check — anyone can trigger it after the timelock: [5](#0-4) 

The `unsafe_refund_timelock_sec` defaults to 14 days, giving the DAO a window to reject, but the window is finite and the DAO must actively monitor: [6](#0-5) 

### Impact Explanation
**Immediate (Medium):** The attacker's refund request occupies the single slot for that UTXO. The legitimate user cannot create their own refund request until the DAO/Operator calls `reject_refund`. This puts the bridge in a stuck state requiring operator intervention for every targeted deposit.

**Escalated (Critical):** If the relayer also fails to finalize the deposit via `verify_deposit` within 14 days AND the DAO/Operator does not reject the malicious request, the attacker calls `execute_refund` and the BTC is sent to the attacker's address — a direct theft of user funds.

The `deposit_msg` needed to construct the attack is publicly observable: `get_user_deposit_address` emits a `LogDepositAddress` event containing the full `deposit_msg`: [7](#0-6) 

### Likelihood Explanation
The attack is realistic for any deposit where `deposit_msg.refund_address` is `None`. The attacker only needs to:
1. Watch NEAR events for `LogDepositAddress` to obtain the `deposit_msg`.
2. Watch the BTC chain for the corresponding deposit transaction.
3. Call `request_refund` before the legitimate user or relayer does, attaching the required storage deposit.

The 14-day `unsafe_refund_timelock_sec` provides a DAO mitigation window, but the stuck-state impact (blocking the user's own refund) is immediate and unconditional.

### Recommendation
1. **Bind the refund address to the depositor at request time.** Record `env::predecessor_account_id()` as the request owner and require that only the owner (or DAO/Operator) can call `execute_refund` for that request.
2. **Alternatively, allow multiple refund requests per UTXO** (analogous to the report's option 1), selecting the one to execute via DAO/Operator approval, so a malicious first request does not block legitimate ones.
3. **Or, require `deposit_msg.refund_address` to be set** at deposit time (non-`None`) so the refund destination is fixed before any NEAR account can interact with the refund flow.

### Proof of Concept
1. Alice calls `get_user_deposit_address` with `deposit_msg = { recipient_id: "alice.near", refund_address: None }`. The `LogDepositAddress` event is emitted on NEAR, revealing the full `deposit_msg`.
2. Alice sends 1 BTC to the derived deposit address on Bitcoin.
3. The relayer is slow or offline; `verify_deposit` is not called.
4. Attacker Eve monitors NEAR events and the BTC chain. She calls `request_refund(deposit_msg, "attacker_btc_address", tx_bytes, vout, proof, None)` with a valid SPV proof and the required storage deposit.
5. `request_refund_callback` stores `RefundRequest { refund_address: "attacker_btc_address", ... }` for Alice's UTXO.
6. Alice tries to call `request_refund` with her own BTC address — it panics: `"Refund request already exists for this UTXO"`.
7. The DAO does not notice within 14 days (`unsafe_refund_timelock_sec`).
8. Eve calls `execute_refund(utxo_storage_key, None)`. The bridge builds a refund transaction paying 1 BTC (minus gas fee) to `"attacker_btc_address"` and submits it for MPC signing.
9. Alice's 1 BTC is stolen. [8](#0-7)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L294-308)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
        }
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

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
