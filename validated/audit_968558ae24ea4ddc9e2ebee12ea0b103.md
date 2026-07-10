### Title
`claim_lost_found` Blocked by Pause Causes Users to Require DAO Intervention to Recover Their Own nBTC - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary

When the bridge contract is paused, users who have nBTC credited to them in the `lost_found` map cannot call `claim_lost_found` to recover those funds. The function carries `#[pause(except(roles(Role::DAO)))]`, so only the DAO can invoke it while paused. This creates a stuck state where users cannot exit with their own nBTC without DAO intervention — a direct analog to M-24's pattern of a user-exit path being gated behind a privileged prerequisite.

### Finding Description

The `lost_found` map is populated when a `cancel_withdraw` RBF succeeds but the subsequent nBTC transfer back to the user fails. At that point the user's nBTC is held inside the contract under their account ID in `data.lost_found`. The only way to recover it is `claim_lost_found`:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn claim_lost_found(&mut self) -> Promise {
    assert_one_yocto();
    let account_id = env::predecessor_account_id();
    let amount = self
        .data_mut()
        .lost_found
        .remove(&account_id)
        .expect("The account does not have lostfound");
    self.internal_transfer_nbtc(&account_id, amount)
}
```

The `#[pause(except(roles(Role::DAO)))]` macro from `near-plugins` causes the function to panic for any non-DAO caller while the contract is paused. The `PauseManager` role (distinct from `DAO`) can trigger a pause unilaterally. Once paused, a regular user with nBTC in `lost_found` is completely blocked from recovering their funds until the DAO explicitly unpauses the contract.

The same `#[pause(except(roles(Role::DAO)))]` guard also blocks `execute_refund` and `request_refund`, meaning users with BTC locked in deposit addresses cannot initiate or complete a refund while paused either. However, `claim_lost_found` is the sharpest case: the nBTC is already inside the NEAR contract, already attributed to the user, and there is no security rationale for blocking its withdrawal during a pause.

### Impact Explanation

Users who have nBTC in `lost_found` (a realistic post-`cancel_withdraw` state) cannot recover those tokens while the contract is paused. The funds are not lost permanently, but they are inaccessible for the entire duration of the pause without DAO action. This matches the allowed Medium impact: **"Harmful smart-contract behavior without direct funds theft, including... stuck bridge state requiring operator intervention."**

### Likelihood Explanation

A pause can be triggered by any account holding `Role::PauseManager`, which is a separate role from `Role::DAO`. The `PauseManager` role is granted during `add_super_admin` and at initialization. Any pause event — whether routine maintenance, an incident response, or a compromised `PauseManager` key — immediately blocks all users with pending `lost_found` balances. The `lost_found` state is a normal operational outcome of the `cancel_withdraw` flow, so affected users will exist in production.

### Recommendation

Remove the pause guard from `claim_lost_found` (and analogously from `execute_refund`), or change the guard to `#[pause(except(roles(Role::DAO, /* any user */)))]` so that users can always recover funds already attributed to them in contract state. The pause is intended to halt new bridge activity, not to trap funds that are already owed to users. The fix mirrors the M-24 mitigation: allow the user-exit path unconditionally when the protocol is not in a fully frozen/emergency state.

### Proof of Concept

1. User initiates a withdrawal via `ft_transfer_call` → `ft_on_transfer`. The bridge selects UTXOs and requests an MPC signature.
2. The withdrawal stalls on-chain. DAO/Operator calls `cancel_withdraw`, which triggers an RBF transaction. The RBF succeeds, but the cross-contract nBTC transfer back to the user fails. The bridge stores the user's nBTC amount in `data.lost_found[user_account_id]`.
3. A `PauseManager` (not necessarily DAO) calls `pa_pause` to pause the contract.
4. The user calls `claim_lost_found` to recover their nBTC. The call panics because `#[pause(except(roles(Role::DAO)))]` rejects non-DAO callers while paused.
5. The user's nBTC remains locked in `lost_found` for the entire duration of the pause. Only a DAO `pa_unpause` call can unblock them.

Relevant code locations:

- `claim_lost_found` with `#[pause(except(roles(Role::DAO)))]`: [1](#0-0) 
- `execute_refund` with the same guard: [2](#0-1) 
- `request_refund` with the same guard: [3](#0-2) 
- `PauseManager` role definition (separate from `DAO`): [4](#0-3) 
- Pause role assignment at init (PauseManager ≠ DAO): [5](#0-4) 
- `lost_found` map in contract state: [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L449-460)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_lost_found(&mut self) -> Promise {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let amount = self
            .data_mut()
            .lost_found
            .remove(&account_id)
            .expect("The account does not have lostfound");
        self.internal_transfer_nbtc(&account_id, amount)
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L509-535)
```rust
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

**File:** contracts/satoshi-bridge/src/lib.rs (L140-141)
```rust
    pub lost_found: IterableMap<AccountId, u128>,
    pub acc_collected_protocol_fee: u128,
```

**File:** contracts/satoshi-bridge/src/lib.rs (L220-223)
```rust
        contract.acl_init_super_admin(env::predecessor_account_id());
        contract.acl_grant_role(Role::DAO.into(), env::predecessor_account_id());
        contract.acl_grant_role(Role::PauseManager.into(), env::predecessor_account_id());
        contract.acl_grant_role(Role::UnpauseManager.into(), env::predecessor_account_id());
```
