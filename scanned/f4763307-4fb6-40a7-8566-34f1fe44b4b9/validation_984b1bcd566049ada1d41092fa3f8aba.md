### Title
`OmniToken` single immutable `controller` prevents `omni-bridge` from minting/burning tokens deployed via `LegacyController`, permanently locking bridged funds — (`near/token-deployer/src/lib.rs`)

---

### Summary

The `token-deployer` contract grants both `Role::Controller` (the `omni-bridge`) and `Role::LegacyController` (the legacy rainbow-token-connector bridge) the ability to call `deploy_token`. When a token is deployed, its `controller` is hard-coded to `env::predecessor_account_id()` — the immediate caller. Because `OmniToken` exposes no `update_controller` function, this assignment is permanent. Tokens deployed by the `LegacyController` therefore have the legacy bridge as their sole authorized minter/burner. The `omni-bridge` cannot mint or burn those tokens, so any `fin_transfer` that targets such a token will always revert, permanently locking the user's funds that were already locked or burned on the source chain.

---

### Finding Description

**Root cause — `token-deployer` sets controller to caller:** [1](#0-0) 

Both `Role::Controller` and `Role::LegacyController` may call `deploy_token`. The `new` initializer of the freshly-created `OmniToken` receives `controller: env::predecessor_account_id()`, which in the token-deployer's execution context is whichever bridge contract made the call. A token deployed by the legacy bridge therefore has the legacy bridge's account ID as its permanent controller.

**Root cause — `OmniToken` enforces a single, immutable controller:** [2](#0-1) 

`assert_controller` is the sole guard on `mint` and `burn`: [3](#0-2) 

There is no `set_controller`, `update_controller`, or equivalent function anywhere in `OmniToken`. The controller field set at `new` is final.

**`omni-bridge` cannot mint/burn tokens it does not control:**

During `fin_transfer`, the bridge calls `burn_tokens_if_needed` and `send_tokens` (which calls `mint`) for every token in its `deployed_tokens` / `deployed_tokens_v2` sets: [4](#0-3) 

If the token's controller is the legacy bridge rather than the `omni-bridge`, the cross-contract `mint` call panics with `MissingPermission`, reverting the entire `fin_transfer` transaction.

**`update_tokens_controller` does not help:**

The only controller-update path in `omni-bridge` calls `set_controller_for_tokens` on an *external factory* (the old rainbow-token-connector factory), not on `OmniToken` itself: [5](#0-4) 

`OmniToken` has no such entry point, so there is no on-chain path to transfer control of a deployed `OmniToken` to the `omni-bridge`.

---

### Impact Explanation

A user who bridges a token whose NEAR-side `OmniToken` was deployed by the `LegacyController` will have their assets locked or burned on the source chain (Ethereum, Solana, etc.) while every subsequent `fin_transfer` call on NEAR reverts. Because the controller is immutable and the `omni-bridge` has no way to acquire minting rights, the funds are permanently frozen. This matches the "permanent freezing of bridged funds" critical impact category.

---

### Likelihood Explanation

The `LegacyController` role is explicitly present in the deployed `token-deployer` and is intended for the old rainbow-token-connector bridge. During the ongoing migration from the legacy bridge to the omni-bridge, the DAO is expected to register legacy-deployed tokens in the omni-bridge via `add_deployed_tokens`. Once a legacy-controlled token is added to `deployed_tokens`, every inbound transfer for that token will fail permanently. No private-key compromise or malicious actor is required — the failure mode is triggered by the normal migration workflow.

---

### Recommendation

1. **Add `update_controller` to `OmniToken`**: expose a function callable only by the current `controller` that transfers control to a new address, allowing the DAO to migrate ownership from the legacy bridge to the `omni-bridge` before registering tokens.
2. **Alternatively, fix the controller at deploy time**: in `token-deployer::deploy_token`, replace `env::predecessor_account_id()` with a stored, immutable `omni_bridge` account ID so that all tokens, regardless of which authorized caller triggers deployment, are always controlled by the `omni-bridge`.
3. **Guard `add_deployed_tokens`**: before inserting a token into `deployed_tokens`, verify on-chain that `env::current_account_id()` (the `omni-bridge`) is the token's controller, and revert if not.

---

### Proof of Concept

1. DAO grants `Role::LegacyController` to the legacy rainbow-token-connector bridge (`factory.bridge.near`).
2. `factory.bridge.near` calls `token-deployer.deploy_token(account_id = "eth-usdc.token-deployer.near", metadata = …)`.
   - Inside `token-deployer`, `env::predecessor_account_id()` = `factory.bridge.near`.
   - The new `OmniToken` is initialized with `controller = factory.bridge.near`.
3. DAO calls `omni-bridge.add_deployed_tokens([{token_id: "eth-usdc.token-deployer.near", …}])`, registering the token.
4. A user locks USDC on Ethereum and a relayer submits the proof via `omni-bridge.fin_transfer(…)`.
5. `fin_transfer_callback` → `process_fin_transfer_to_near` → `send_tokens` → cross-contract call to `eth-usdc.token-deployer.near.mint(recipient, amount, …)`.
6. `OmniToken::mint` calls `assert_controller()`: `env::predecessor_account_id()` = `omni-bridge` ≠ `factory.bridge.near` → **panic: MissingPermission**.
7. The entire `fin_transfer` transaction reverts. The transfer is not marked finalized, but every retry produces the same panic. The user's Ethereum USDC is permanently locked in `OmniBridge.sol` with no recourse. [1](#0-0) [6](#0-5) [2](#0-1) [7](#0-6)

### Citations

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

**File:** near/omni-token/src/lib.rs (L26-32)
```rust
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct OmniToken {
    controller: AccountId,
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
}
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

**File:** near/omni-token/src/lib.rs (L125-152)
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

        if let Some(msg) = msg {
            self.token
                .internal_deposit(&env::predecessor_account_id(), amount.into());

            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
        }
    }

    fn burn(&mut self, amount: U128) {
        self.assert_controller();

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
    }
}
```

**File:** near/omni-bridge/src/lib.rs (L1532-1556)
```rust
    #[access_control_any(roles(Role::DAO))]
    #[payable]
    pub fn add_deployed_tokens(&mut self, tokens: Vec<AddDeployedTokenArgs>) {
        require!(
            env::attached_deposit()
                >= NEP141_DEPOSIT
                    .saturating_mul(tokens.len().try_into().near_expect(BridgeError::Cast)),
            BridgeError::NotEnoughAttachedDeposit.as_ref()
        );

        for token_info in tokens {
            self.deployed_tokens.insert(&token_info.token_id);
            self.deployed_tokens_v2
                .insert(&token_info.token_id, &token_info.token_address.get_chain());
            self.add_token(
                &token_info.token_id,
                &token_info.token_address,
                token_info.decimals,
                token_info.decimals,
            );
            ext_token::ext(token_info.token_id.clone())
                .with_static_gas(STORAGE_DEPOSIT_GAS)
                .with_attached_deposit(NEP141_DEPOSIT)
                .storage_deposit(&env::current_account_id(), Some(true))
                .detach();
```

**File:** near/omni-bridge/src/lib.rs (L1678-1688)
```rust
    #[access_control_any(roles(Role::DAO, Role::TokenControllerUpdater))]
    pub fn update_tokens_controller(
        &self,
        factory_account_id: AccountId,
        tokens_accounts_id: Vec<AccountId>,
    ) {
        ext_bridge_token_facory::ext(factory_account_id)
            .with_static_gas(UPDATE_CONTROLLER_GAS)
            .set_controller_for_tokens(tokens_accounts_id)
            .detach();
    }
```

**File:** near/omni-bridge/src/lib.rs (L1806-1813)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
    }
```
