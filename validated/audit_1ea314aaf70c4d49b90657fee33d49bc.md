### Title
NEAR Storage Deposits Permanently Locked in Bridge Contract — (File: `contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

Multiple `#[payable]` bridge functions accept NEAR token deposits as storage/anti-spam fees, but the contract provides no mechanism to withdraw these accumulated NEAR tokens. They are permanently locked in the contract with no recovery path.

---

### Finding Description

Three public entry points in the satoshi-bridge contract are `#[payable]` and require a minimum attached NEAR deposit:

**1. `request_refund`** — explicitly documented as non-refundable:

> "Requires an attached deposit of at least `required_balance_for_request_refund()`. The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee." [1](#0-0) 

The internal implementation enforces this: [2](#0-1) 

**2. `execute_refund`** — also `#[payable]`, enforces a minimum deposit: [3](#0-2) 

The deposit check is in `resolve_execute_refund_timelock`: [4](#0-3) 

**3. `safe_verify_deposit` / `verify_deposit_v2` (safe path)** — requires attached NEAR for storage: [5](#0-4) 

In all three cases, the attached NEAR tokens flow into the contract's balance and are never returned to the caller. The only withdrawal function in the contract is `withdraw_protocol_fee`, which exclusively handles **nBTC tokens** (the NEP-141 fungible token), not native NEAR: [6](#0-5) 

There is no `withdraw_near` or equivalent function anywhere in the management API. 

---

### Impact Explanation

Every call to `request_refund`, `execute_refund`, or `safe_verify_deposit` permanently locks NEAR tokens in the contract. Over the bridge's operational lifetime, these deposits accumulate with no recovery path short of a contract upgrade. This constitutes permanent locking of protocol-adjacent funds (NEAR tokens held by the bridge contract) with no authorized withdrawal mechanism.

**Impact: Medium** — Harmful smart-contract behavior without direct BTC/nBTC theft; permanent locking of NEAR tokens requiring operator intervention (contract upgrade) to recover.

---

### Likelihood Explanation

**Likelihood: High** — Every refund request and every safe deposit call locks NEAR tokens. These are normal, publicly reachable bridge operations. Any user submitting a refund request or any relayer calling `safe_verify_deposit` triggers the accumulation. No special conditions are required.

---

### Recommendation

Add a DAO-gated function to withdraw accumulated NEAR tokens from the contract balance, analogous to `withdraw_protocol_fee` for nBTC:

```rust
#[payable]
#[access_control_any(roles(Role::DAO))]
pub fn withdraw_near(&mut self, amount: NearToken, recipient: AccountId) -> Promise {
    assert_one_yocto();
    Promise::new(recipient).transfer(amount)
}
```

Also consider returning excess attached NEAR (above the required minimum) to callers of `request_refund` and `execute_refund`.

---

### Proof of Concept

1. Any NEAR account calls `request_refund(...)` with the required minimum NEAR deposit attached.
2. The NEAR tokens are accepted by the contract and credited to its balance.
3. The `request_refund_callback` stores the `RefundRequest` but never transfers NEAR back to the caller.
4. The DAO calls `withdraw_protocol_fee` — this only moves nBTC, not NEAR.
5. No other function in `management.rs` or anywhere in the contract allows withdrawing NEAR tokens.
6. The NEAR tokens are permanently locked. Repeat for every subsequent `request_refund`, `execute_refund`, and `safe_verify_deposit` call. [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-510)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
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

**File:** contracts/satoshi-bridge/src/refund.rs (L146-149)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L202-205)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L496-581)
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
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L181-184)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_safe_deposit(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L1-30)
```rust
use crate::{
    assert_one_yocto, env, near, require, AccessControllable, Account, AccountId, ConfigUpdate,
    Contract, ContractExt, HashSet, Promise, Role, U128,
};

use near_plugins::access_control_any;

#[near]
impl Contract {
    /// Withdraw a specified amount of protocol fee to the owner’s account.
    ///
    /// # Arguments
    ///
    /// * `amount` - Specify the amount to withdraw; if not specified, it will be the full amount.
    ///
    /// # Returns
    ///
    /// bool - Whether the Withdraw was successful.
    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn withdraw_protocol_fee(&mut self, amount: Option<U128>) -> Promise {
        assert_one_yocto();
        let total_protocol_fee = self.data().cur_available_protocol_fee;
        let amount = amount.map_or(total_protocol_fee, |v| v.0);
        require!(amount > 0 && amount <= total_protocol_fee, "Invalid amount");
        self.data_mut().cur_available_protocol_fee -= amount;
        self.data_mut().acc_claimed_protocol_fee += amount;
        self.internal_withdraw_protocol_fee(amount)
    }
}
```
