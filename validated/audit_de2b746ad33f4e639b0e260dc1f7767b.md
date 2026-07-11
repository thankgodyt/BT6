### Title
`Role::Operator` Has Excessive Fund-Redirection Permissions Beyond Operational Scope - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The `Role::Operator` in the satoshi-bridge contract is documented as a "general operational role for administrative tasks that do not require full DAO consensus," analogous to a custodian that should only perform limited operational actions. However, the `Operator` role is granted access to `cancel_withdraw` and `active_utxo_management` (and their RBF/cancel variants), both of which accept a caller-supplied `output: Vec<TxOut>` that is passed without on-chain destination validation into the MPC signing pipeline. A malicious or compromised Operator can construct BTC transactions that redirect bridge-controlled UTXOs to an arbitrary BTC address, draining bridge funds.

### Finding Description
The `Role::Operator` is granted access to four fund-moving functions in `bridge.rs`:

1. **`cancel_withdraw`** (lines 283–299): Accepts `output: Vec<TxOut>` and passes it directly to `cancel_withdraw_chain_specific`. This function is intended to RBF-cancel a stuck user withdrawal, but the destination outputs are entirely Operator-controlled with no on-chain check that they route back to the bridge's change address or the original user.

2. **`active_utxo_management`** (lines 369–375): Accepts `input: Vec<OutPoint>` (bridge UTXOs to spend) and `output: Vec<TxOut>` (destinations), passed directly to `active_utxo_management_chain_specific`. An Operator can select any bridge UTXO as input and route the value to any BTC address.

3. **`active_utxo_management_rbf`** (lines 384–400) and **`cancel_active_utxo_management`** (lines 409–428): Same pattern — Operator-supplied `output: Vec<TxOut>` fed into the MPC signing pipeline.

In all four cases, the MPC (Chain Signatures) service is a general-purpose signer: it signs whatever payload the bridge contract submits. The bridge contract is the sole gatekeeper for output validity, and it performs no destination check on Operator-supplied outputs. Once the MPC signs the transaction, the BTC is irreversibly sent to the Operator-specified address on the Bitcoin network.

By contrast, the `withdraw_protocol_fee` function (the only explicit fund-withdrawal function) is correctly restricted to `Role::DAO` only. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
A malicious Operator can:
- Call `cancel_withdraw` on any pending user withdrawal, supplying their own BTC address as the sole output. The MPC signs the RBF transaction; the user's BTC (which was being held in bridge UTXOs) is sent to the attacker. The user's nBTC remains locked in the bridge with no corresponding BTC backing.
- Call `active_utxo_management` selecting any bridge UTXO as input and their own BTC address as output. The MPC signs the transaction; bridge-controlled BTC is drained. The nBTC supply remains unbacked.

Both paths result in **significant, irreversible loss of bridge-controlled BTC funds** and break the 1:1 nBTC/BTC backing invariant. This maps to the allowed critical impact: *"Significant loss, theft, destruction, or permanent locking of user or protocol funds."* [1](#0-0) [4](#0-3) 

### Likelihood Explanation
The `Operator` role is granted by the `DAO` via `extend_operators`. An attacker who socially engineers the DAO into granting them the `Operator` role — or who compromises an existing Operator key — can immediately exploit this. The role is intended for routine operational tasks (relayer management, UTXO consolidation), making it a plausible target for social engineering: the DAO may not scrutinize Operator grants as carefully as DAO-level grants. This mirrors the exact exploit scenario in the reference report (Eve tricks governance into granting her the custodian role). [5](#0-4) [6](#0-5) 

### Recommendation
**Short term:** Restrict `cancel_withdraw`, `active_utxo_management`, `active_utxo_management_rbf`, and `cancel_active_utxo_management` to `Role::DAO` only, removing `Role::Operator` from the `#[access_control_any]` guards on these four functions. Document explicitly that any account with `Role::Operator` currently has the ability to redirect bridge-controlled BTC, so existing Operator grants can be audited.

**Long term:** Add on-chain output validation inside `cancel_withdraw_chain_specific` and `active_utxo_management_chain_specific` to assert that all outputs route exclusively to the bridge's own `change_address` or the original user's registered withdrawal address. This removes the dependency on Operator honesty and eliminates the attack surface regardless of role assignment. [1](#0-0) [7](#0-6) 

### Proof of Concept
1. DAO calls `extend_operators([attacker.near])` — attacker now holds `Role::Operator`.
2. A user initiates a withdrawal: sends nBTC to the bridge via `ft_transfer_call`; bridge creates a pending BTC transaction spending bridge UTXOs.
3. Attacker calls `cancel_withdraw(original_btc_pending_verify_id, [TxOut { value: full_amount, script_pubkey: attacker_btc_address }])` with 1 yoctoNEAR attached.
4. `cancel_withdraw_chain_specific` builds an RBF transaction with the attacker's address as the sole output and submits it to the MPC for signing.
5. MPC signs the transaction; attacker broadcasts it to Bitcoin. The user's BTC is sent to the attacker's address.
6. The user's nBTC remains locked in the bridge with no BTC backing; the bridge's UTXO set is depleted by the stolen amount.

Alternatively, attacker calls `active_utxo_management(all_bridge_utxos, [TxOut { value: total, script_pubkey: attacker_btc_address }])` to drain the entire bridge UTXO set in a single MPC-signed transaction. [1](#0-0) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L283-299)
```rust
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);

        self.cancel_withdraw_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L369-400)
```rust
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn active_utxo_management(&mut self, input: Vec<OutPoint>, output: Vec<TxOut>) {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        self.active_utxo_management_chain_specific(account_id, input, output);
    }

    /// The initiator of active UTXO management accelerates the transaction by increasing the gas fee.
    ///
    /// # Arguments
    ///
    /// * `original_btc_pending_verify_id` - Pending verify ID of the original transaction.
    /// * `output` - Modified output.
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn active_utxo_management_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
    ) {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);
        self.active_utxo_management_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L409-428)
```rust
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_active_utxo_management(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
    ) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);
        self.cancel_active_utxo_management_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L20-29)
```rust
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
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L79-104)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn extend_operators(&mut self, operators: Vec<AccountId>) {
        assert_one_yocto();
        for operator in operators {
            let is_success = self
                .acl_grant_role(Role::Operator.into(), operator.clone())
                .unwrap();
            require!(is_success, format!("Already exist operator: {}", operator));
            if !self.check_account_exists(&operator) {
                self.internal_set_account(&operator, Account::new(&operator));
            }
        }
    }

    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn remove_operators(&mut self, operators: Vec<AccountId>) {
        assert_one_yocto();
        for operator in operators {
            let is_success = self
                .acl_revoke_role(Role::Operator.into(), operator.clone())
                .unwrap();
            require!(is_success, format!("Invalid operator: {}", operator));
        }
    }
```

**File:** contracts/satoshi-bridge/src/lib.rs (L101-114)
```rust
#[derive(AccessControlRole, Deserialize, Serialize, Copy, Clone)]
#[serde(crate = "near_sdk::serde")]
pub enum Role {
    DAO,
    Operator,
    PauseManager,
    UpgradableCodeStager,
    UpgradableCodeDeployer,
    UnrestrictedRelayer,
    RelayerManager,
    RefundOperator,
    UnpauseManager,
    MigrationOperator,
}
```
