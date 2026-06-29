Looking at the exact code in `near/token-deployer/src/lib.rs` and `near/omni-token/src/lib.rs`, I can trace the full call path.

The vulnerability is real and concrete. Here is the full analysis:

---

### Title
`LegacyController` Gains Unauthorized `mint`/`burn` Authority Over Deployed Tokens via `deploy_token` Controller Injection — (`near/token-deployer/src/lib.rs`)

### Summary

`TokenDeployer::deploy_token` passes `env::predecessor_account_id()` as the `controller` argument to `OmniToken::new`. Because the `LegacyController` role is permitted to call `deploy_token`, any account holding that role can deploy a token with itself as controller, then freely call `mint()` and `burn()` on that token.

### Finding Description

In `near/token-deployer/src/lib.rs`, `deploy_token` is gated by `Role::Controller | Role::LegacyController`: [1](#0-0) 

The critical line is:

```rust
json!({"controller": env::predecessor_account_id(), "metadata": metadata})
``` [2](#0-1) 

This means whoever calls `deploy_token` is written into the new token's `controller` field — not the bridge contract.

In the **intended flow**, the bridge contract calls `ext_deployer::ext(deployer).deploy_token(...)`, so `env::predecessor_account_id()` inside the token-deployer is the bridge contract, and the bridge becomes the controller: [3](#0-2) 

In the **attack flow**, a `LegacyController` account calls `token_deployer.deploy_token(new_token_id, metadata)` directly. `env::predecessor_account_id()` is now the attacker's account, so the new token is initialized with the attacker as controller.

`OmniToken::new` has a guard, but it only checks that the **token-deployer** (parent account) is the caller of `new` — it does not validate who the `controller` argument is: [4](#0-3) 

Once deployed, `mint` and `burn` are gated solely by `assert_controller()`, which checks `caller == self.controller`: [5](#0-4) [6](#0-5) [7](#0-6) 

Since the attacker IS the controller, both `mint` and `burn` succeed unconditionally.

### Impact Explanation

A `LegacyController` account can:
1. Deploy a token (sub-account of the token-deployer) with itself as controller.
2. Call `mint()` to create unbacked supply and distribute it to users.
3. Call `burn()` to destroy any user balance (after the user has registered storage and received tokens).

The token is a legitimate `omni-token` WASM instance deployed under the token-deployer's namespace, making it indistinguishable from a real bridge token to users and integrators. The bridge's own `deployed_tokens` registry would not contain this token (since the bridge's `deploy_token_internal` was bypassed), but the token itself is fully functional.

### Likelihood Explanation

The `LegacyController` role exists explicitly in the production contract and is grantable by the DAO. The role is designed for migration/legacy use cases, meaning it is expected to be granted to non-bridge accounts. Any such account can immediately exploit this without further preconditions — no key leakage, no validator collusion, no MPC compromise required. The call is a single direct transaction.

### Recommendation

The `deploy_token` function should not use `env::predecessor_account_id()` as the controller. Instead, the token-deployer should store the bridge contract's `AccountId` as a field at initialization time and always pass that stored address as the controller, regardless of who calls `deploy_token`:

```rust
pub struct TokenDeployer {
    global_code_hash: CryptoHash,
    bridge_controller: AccountId,  // add this
}
```

Then in `deploy_token`:
```rust
json!({"controller": self.bridge_controller, "metadata": metadata})
```

This ensures the bridge contract is always the controller of any deployed token, regardless of which role calls `deploy_token`.

### Proof of Concept

On localnet:
1. Deploy `token-deployer` with `controller = bridge.near`, `dao = dao.near`.
2. As `dao.near`, call `acl_grant_role(role = "LegacyController", account_id = "attacker.near")`.
3. As `attacker.near`, call `token_deployer.deploy_token(account_id = "evil.token_deployer.near", metadata = {...})` with sufficient attached deposit.
4. The token is deployed with `controller = attacker.near`.
5. As `attacker.near`, call `evil.token_deployer.near.mint(account_id = "victim.near", amount = "1000000000000000000000000")`.
6. Assert the call succeeds and `ft_balance_of("victim.near")` returns the minted amount — confirming unbacked supply creation.
7. As `attacker.near`, call `evil.token_deployer.near.burn(amount = ...)` after self-registering — confirming burn authority.

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L2446-2453)
```rust
        ext_deployer::ext(deployer)
            .with_static_gas(DEPLOY_TOKEN_GAS)
            .with_attached_deposit(attached_deposit.saturating_sub(required_deposit))
            .deploy_token(token_id.clone(), metadata)
            .then(
                Self::ext(env::current_account_id())
                    .deploy_token_by_deployer_callback(token_address, token_id),
            )
```

**File:** near/omni-token/src/lib.rs (L57-60)
```rust
        require!(
            env::predecessor_account_id().as_str() == deployer_account,
            "Only the deployer account can init this contract"
        );
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

**File:** near/omni-token/src/lib.rs (L133-133)
```rust
        self.assert_controller();
```

**File:** near/omni-token/src/lib.rs (L147-147)
```rust
        self.assert_controller();
```
