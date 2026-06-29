The vulnerability is real and concrete. Here is the full analysis:

---

### Title
`LegacyController` Gains Unauthorized Mint/Burn Authority Over Deployed Tokens via `deploy_token()` Controller Injection — (`near/token-deployer/src/lib.rs`)

### Summary

`TokenDeployer::deploy_token()` passes `env::predecessor_account_id()` directly as the `controller` argument to `OmniToken::new`. Because `Role::LegacyController` is authorized to call `deploy_token()`, any account holding that role can deploy a new bridge token with **itself** as the controller, granting itself permanent, unrestricted `mint()` and `burn()` authority over that token.

### Finding Description

`deploy_token` in `near/token-deployer/src/lib.rs` is gated by `#[access_control_any(roles(Role::Controller, Role::LegacyController))]`: [1](#0-0) 

The function call that initializes the new token passes the **caller** as controller: [2](#0-1) 

`OmniToken::new` accepts whatever `AccountId` is supplied as `controller` and stores it verbatim — it only checks that the predecessor is the parent deployer account, not that the controller is the bridge contract: [3](#0-2) 

`TokenDeployer` does **not** store the bridge contract address in its state: [4](#0-3) 

During initialization, the `controller` parameter is only used to grant `Role::Controller` in the ACL — it is never persisted for use in `deploy_token`: [5](#0-4) 

`mint()` and `burn()` on `OmniToken` are gated solely by `assert_controller()`, which checks `env::predecessor_account_id() == self.controller`: [6](#0-5) [7](#0-6) [8](#0-7) 

### Impact Explanation

A `LegacyController` account calls `token_deployer.deploy_token(new_token_id, metadata)`. The token is deployed with `controller = legacy_controller_account`. That account can then:

- Call `mint(any_account, large_amount, None)` to create unbacked supply of a bridge token, enabling theft of collateral on the source chain.
- Call `burn(amount)` to destroy any user's balance after transferring it to itself.

This directly violates the invariant that only the bridge contract holds mint/burn authority over deployed bridge tokens.

### Likelihood Explanation

The `LegacyController` role exists explicitly in the production role enum and is a named, supported access path — not a misconfiguration. Any account the DAO grants `LegacyController` to can trigger this immediately with a single transaction. No key compromise, no validator collusion, and no additional preconditions are required beyond holding the role.

### Recommendation

Store the canonical bridge controller address in `TokenDeployer` state and use it — not `env::predecessor_account_id()` — when constructing the `OmniToken::new` call:

```rust
pub struct TokenDeployer {
    global_code_hash: CryptoHash,
    controller: AccountId,   // bridge contract, set at init, immutable
}
```

Then in `deploy_token`:
```rust
json!({"controller": self.controller, "metadata": metadata})
```

### Proof of Concept

1. Deploy `token-deployer` on localnet, passing `bridge.near` as `controller` and `dao.near` as `dao`.
2. As `dao.near`, call `acl_grant_role(role = "LegacyController", account_id = "attacker.near")`.
3. As `attacker.near`, call `token_deployer.deploy_token(account_id = "evil-token.attacker.near", metadata = {...})` with sufficient attached deposit.
4. The token is deployed with `controller = attacker.near`.
5. As `attacker.near`, call `evil-token.attacker.near.mint(account_id = "attacker.near", amount = "1000000000000000000000000", msg = null)`.
6. Assert the call succeeds and `ft_balance_of(attacker.near)` returns the minted amount — confirming unbacked supply creation with no bridge deposit.

### Citations

**File:** near/token-deployer/src/lib.rs (L39-41)
```rust
pub struct TokenDeployer {
    global_code_hash: CryptoHash,
}
```

**File:** near/token-deployer/src/lib.rs (L46-56)
```rust
    pub fn new(controller: AccountId, dao: AccountId, global_code_hash: Base58CryptoHash) -> Self {
        let mut contract = Self {
            global_code_hash: global_code_hash.into(),
        };

        contract.acl_init_super_admin(near_sdk::env::predecessor_account_id());
        contract.acl_grant_role(Role::DAO.into(), dao.clone());
        contract.acl_grant_role(Role::Controller.into(), controller);
        contract.acl_transfer_super_admin(dao);
        contract
    }
```

**File:** near/token-deployer/src/lib.rs (L58-73)
```rust
    #[payable]
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

**File:** near/omni-token/src/lib.rs (L49-63)
```rust
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
```

**File:** near/omni-token/src/lib.rs (L98-104)
```rust
    fn assert_controller(&self) {
        let caller = env::predecessor_account_id();
        require!(
            caller == self.controller,
            TokenError::MissingPermission.as_ref()
        );
    }
```

**File:** near/omni-token/src/lib.rs (L125-133)
```rust
impl MintAndBurn for OmniToken {
    #[payable]
    fn mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_controller();
```

**File:** near/omni-token/src/lib.rs (L146-151)
```rust
    fn burn(&mut self, amount: U128) {
        self.assert_controller();

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
    }
```
