The exploit path is real and concrete. Here is the full analysis:

---

### Title
LegacyController Can Deploy OmniToken With Itself as Controller and Mint Unbacked Tokens — (`near/token-deployer/src/lib.rs`)

### Summary

`deploy_token` in `token-deployer` is callable by both `Role::Controller` and `Role::LegacyController`, but it unconditionally passes `env::predecessor_account_id()` as the `controller` argument to the new `OmniToken`. A `LegacyController`-role account can therefore deploy a fresh `OmniToken` where it is the controller, then call `mint` on that token directly to create unbacked supply.

### Finding Description

**Step 1 — Access gate on `deploy_token`:**

`deploy_token` is guarded by `#[access_control_any(roles(Role::Controller, Role::LegacyController))]`, so any account holding `LegacyController` on the token-deployer can invoke it. [1](#0-0) 

**Step 2 — Controller is set to the caller, not the bridge:**

Inside `deploy_token`, the `controller` field passed to `OmniToken::new` is `env::predecessor_account_id()` — i.e., whoever called `deploy_token`. There is no stored "intended controller" that is substituted here. [2](#0-1) 

**Step 3 — `OmniToken::new` accepts any controller:**

`OmniToken::new` only validates that its *caller* (the token-deployer, via Promise) is the parent account. It stores the `controller` argument verbatim with no further validation. [3](#0-2) 

**Step 4 — `mint` only checks `self.controller`:**

`mint` calls `assert_controller()`, which requires `env::predecessor_account_id() == self.controller`. Since the LegacyController account is now stored as `self.controller`, it can call `mint` freely. [4](#0-3) [5](#0-4) 

**Contrast with intended design:**

The test environment initializes the token-deployer with `controller = bridge_contract.id()`, and the CLAUDE.md documents `controller` as "Bridge contract — can mint/burn". The bridge contract only mints after verifying a cross-chain proof. A `LegacyController` bypasses all of that. [6](#0-5) 

### Impact Explanation

A `LegacyController`-role account can mint an arbitrary amount of any token it deploys via `token-deployer.deploy_token`. These tokens share the same NEP-141 interface as legitimately bridged tokens. If the token is registered in the bridge's token registry (or traded on DEXes), the attacker can redeem or sell unbacked supply — equivalent to unauthorized minting of bridged funds.

### Likelihood Explanation

The `LegacyController` role is a named, grantable role on the token-deployer. Any account that has been granted this role (e.g., a legacy bridge contract or its operator key) can execute this attack without any additional preconditions, storage deposits aside. The call sequence is two transactions.

### Recommendation

Replace `env::predecessor_account_id()` in `deploy_token` with a stored, immutable controller address (the bridge contract set at initialization), so that regardless of who calls `deploy_token`, the new token's controller is always the bridge:

```rust
// In TokenDeployer state, store:
controller: AccountId,

// In deploy_token:
json!({"controller": self.controller, "metadata": metadata})
```

Alternatively, restrict `deploy_token` to `Role::Controller` only and remove `Role::LegacyController` from that gate, since legacy controllers should not be able to create new tokens with themselves as the mint authority.

### Proof of Concept

```
1. Admin grants LegacyController role to attacker on token-deployer.
2. attacker calls:
     token_deployer.deploy_token(
         account_id = "evil-token.token-deployer.near",
         metadata   = { name: "Evil", symbol: "EVIL", decimals: 18 }
     )
   → OmniToken.new(controller = attacker, ...) is called by token-deployer.
   → self.controller = attacker stored in evil-token state.
3. attacker calls:
     evil_token.mint(account_id = attacker, amount = U128::MAX, msg = None)
   → assert_controller() passes (predecessor == self.controller == attacker).
   → token.internal_deposit(attacker, U128::MAX) executes.
4. Attacker holds U128::MAX unbacked tokens.
``` [7](#0-6) [8](#0-7)

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

**File:** near/omni-tests/src/environment.rs (L423-433)
```rust
        token_deployer
            .call("new")
            .args_json(json!({
                "controller": bridge_contract.id(),
                "dao": AccountId::from_str("dao.near").unwrap(),
                "global_code_hash": global_code_hash,
            }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
```
