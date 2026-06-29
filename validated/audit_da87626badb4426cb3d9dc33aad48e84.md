The code is clear. Let me trace the exact attack path through both contracts.

**`token-deployer/src/lib.rs` — `deploy_token`:** [1](#0-0) 

The function is gated by `Role::Controller | Role::LegacyController`, and it passes `env::predecessor_account_id()` — the caller — directly as the `controller` argument to `OmniToken::new`.

**`omni-token/src/lib.rs` — `OmniToken::new`:** [2](#0-1) 

The only guard in `new` checks that the predecessor is the deployer (parent account), which is satisfied because the cross-contract call comes from the token-deployer contract itself — not from the attacker directly. The `controller` field is set to whatever value was passed in the JSON arguments, which is the attacker's account ID.

**`attach_full_access_key` and `assert_controller`:** [3](#0-2) 

`assert_controller` only checks `env::predecessor_account_id() == self.controller`. Since the attacker IS the controller, this passes unconditionally.

**`mint`:** [4](#0-3) 

`mint` also only calls `self.assert_controller()` — no MPC proof, no bridge verification, no other gate.

---

### Title
LegacyController Can Deploy Token With Itself as Controller, Bypassing MPC-Gated Mint — (`near/token-deployer/src/lib.rs`)

### Summary
`deploy_token` passes `env::predecessor_account_id()` as the `controller` to `OmniToken::new`. Any account holding `Role::LegacyController` can call `deploy_token`, causing the newly deployed token to have the attacker as its controller. The attacker can then call `mint` directly (or first call `attach_full_access_key` to add a full-access key) with no bridge proof or MPC signature required.

### Finding Description
In `token-deployer/src/lib.rs`, `deploy_token` is accessible to both `Role::Controller` and `Role::LegacyController`:

```rust
#[access_control_any(roles(Role::Controller, Role::LegacyController))]
pub fn deploy_token(&mut self, account_id: AccountId, metadata: &BasicMetadata) -> Promise {
    ...
    json!({"controller": env::predecessor_account_id(), "metadata": metadata})
    ...
}
``` [5](#0-4) 

The `controller` field in the `OmniToken` state is set to whoever called `deploy_token`. In `OmniToken::new`, the only guard is that the predecessor of the `new` call equals the deployer (parent account): [6](#0-5) 

This check is satisfied by the cross-contract call from the token-deployer, not by the attacker. The `controller` value in state is set to the attacker's account ID without any further validation.

All privileged operations — `mint`, `burn`, `attach_full_access_key`, `set_metadata`, `set_withdraw_relayer_address` — are gated solely by `assert_controller`, which checks `predecessor == self.controller`: [7](#0-6) 

### Impact Explanation
An attacker holding `LegacyController` on the token-deployer can:
1. Deploy a new `OmniToken` with themselves as controller.
2. Call `mint(attacker, MAX_AMOUNT, None)` directly — no bridge proof, no MPC signature, no cross-chain event required.
3. Alternatively, call `attach_full_access_key(attacker_pk)` to add a full-access key, enabling arbitrary state manipulation.

This constitutes unauthorized minting of bridged tokens, inflating supply and enabling theft of bridged assets. It entirely bypasses the MPC-signed proof-verification gate that is the core security invariant of the bridge.

### Likelihood Explanation
`LegacyController` is a distinct role from `Controller` (the bridge contract), suggesting it is granted to third-party legacy bridge operators. Any such operator — or any party who compromises a `LegacyController` account — can execute this attack. The role is explicitly listed in the access control enum and is grantable by the DAO. [8](#0-7) 

### Recommendation
`deploy_token` should not pass `env::predecessor_account_id()` as the controller. Instead, it should pass a hardcoded or stored bridge contract address (the `Controller` role's account), so that regardless of who calls `deploy_token`, the resulting token's controller is always the bridge. Alternatively, restrict `deploy_token` to `Role::Controller` only and remove `Role::LegacyController` from that access gate.

### Proof of Concept
1. Grant `LegacyController` role to `attacker.near` on the token-deployer.
2. `attacker.near` calls `token-deployer::deploy_token(account_id="evil-token.deployer.near", metadata=...)`.
3. `OmniToken::new` is called with `controller="attacker.near"` — passes the deployer-predecessor check.
4. `attacker.near` calls `evil-token.deployer.near::mint(account_id="attacker.near", amount=U128::MAX, msg=None)`.
5. `assert_controller` passes (`predecessor == controller == attacker.near`).
6. `ft_total_supply` increases by `U128::MAX` with zero bridge proof or MPC involvement.

### Citations

**File:** near/token-deployer/src/lib.rs (L16-24)
```rust
#[derive(AccessControlRole, Copy, Clone)]
pub enum Role {
    DAO = 0,
    PauseManager = 1,
    UpgradableCodeStager = 3,
    UpgradableCodeDeployer = 4,
    Controller = 5,
    LegacyController = 10,
}
```

**File:** near/token-deployer/src/lib.rs (L59-73)
```rust
    #[access_control_any(roles(Role::Controller, Role::LegacyController))]
    pub fn deploy_token(&mut self, account_id: AccountId, metadata: &BasicMetadata) -> Promise {
        Promise::new(account_id)
            .create_account()
            .transfer(env::attached_deposit())
            .use_global_contract(self.global_code_hash)
            .function_call(
                "new".to_string(),
                json!({"controller": env::predecessor_account_id(), "metadata": metadata})
                    .to_string()
                    .into_bytes(),
                NO_DEPOSIT,
                OMNI_TOKEN_INIT_GAS,
            )
    }
```

**File:** near/omni-token/src/lib.rs (L48-79)
```rust
    #[init]
    pub fn new(controller: AccountId, metadata: BasicMetadata) -> Self {
        let current_account_id = env::current_account_id();
        let deployer_account = current_account_id
            .get_parent_account_id()
            .unwrap_or_else(|| {
                env::panic_str(TokenError::InvalidParentAccount.to_string().as_str())
            });

        require!(
            env::predecessor_account_id().as_str() == deployer_account,
            "Only the deployer account can init this contract"
        );

        Self {
            controller,
            // For tokens migrated from Near Intents, storage key is "1"
            token: FungibleToken::new(b"t".to_vec()),
            metadata: LazyOption::new(
                b"m".to_vec(),
                Some(&FungibleTokenMetadata {
                    spec: FT_METADATA_SPEC.to_string(),
                    name: metadata.name,
                    symbol: metadata.symbol,
                    icon: None,
                    reference: None,
                    reference_hash: None,
                    decimals: metadata.decimals,
                }),
            ),
        }
    }
```

**File:** near/omni-token/src/lib.rs (L82-104)
```rust
    pub fn attach_full_access_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_controller();
        Promise::new(env::current_account_id()).add_full_access_key(public_key)
    }

    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }

    pub fn is_using_global_token(&self) -> bool {
        matches!(
            env::current_contract_code(),
            AccountContract::Global(_) | AccountContract::GlobalByAccount(_)
        )
    }

    fn assert_controller(&self) {
        let caller = env::predecessor_account_id();
        require!(
            caller == self.controller,
            TokenError::MissingPermission.as_ref()
        );
    }
```

**File:** near/omni-token/src/lib.rs (L127-144)
```rust
    fn mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_controller();

        if let Some(msg) = msg {
            self.token
                .internal_deposit(&env::predecessor_account_id(), amount.into());

            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
        }
    }
```
