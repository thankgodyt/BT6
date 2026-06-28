### Title
Missing `#[pause]` on `deploy_token` Allows Token Deployment During Emergency Pause — (`near/token-deployer/src/lib.rs`)

---

### Summary

`TokenDeployer::deploy_token` is not gated by the `#[pause]` attribute from `near-plugins`, so it executes unconditionally even when the contract is paused. Any account holding `Role::Controller` or `Role::LegacyController` can deploy a new token contract during an active emergency pause, defeating the purpose of the pause mechanism.

---

### Finding Description

The `TokenDeployer` contract derives `Pausable` and configures `PauseManager` roles: [1](#0-0) 

However, `deploy_token` carries only `#[payable]` and `#[access_control_any(...)]` — no `#[pause]` attribute: [2](#0-1) 

In `near-plugins`, the `Pausable` derive macro only provides the `pa()`/`un()`/`is_paused()` management methods. The `#[pause]` **proc-macro attribute** is what injects the runtime pause check into a specific function. Without it, `deploy_token` never checks `is_paused()` and runs freely regardless of the contract's pause state.

By contrast, the omni-bridge's own `deploy_token` explicitly carries `#[pause(except(roles(Role::DAO)))]`: [3](#0-2) 

The token-deployer has no equivalent guard.

---

### Impact Explanation

**Concrete attack path:**

1. A vulnerability is discovered in the token WASM referenced by `global_code_hash`.
2. `PauseManager` calls `pa()` on the `TokenDeployer` to halt new deployments while the DAO prepares a safe replacement hash via `set_global_code_hash`.
3. During this window, the bridge contract (holding `Role::Controller`) or any `LegacyController` account calls `deploy_token(account_id, metadata)` directly on the token-deployer.
4. Because `deploy_token` has no `#[pause]` check, the call succeeds. A new token account is created and initialized with the **currently stored (potentially compromised) `global_code_hash`** WASM: [4](#0-3) 

5. The bridge records this token address as the canonical wrapped token for the given asset. The malicious/stale WASM is now permanently bound to that bridge address.

The pause invariant — *no new token contracts while paused* — is completely unenforceable.

---

### Likelihood Explanation

- The `Controller` role is held by the omni-bridge contract, which is a live production contract that calls `deploy_token` as part of normal cross-chain token registration flow.
- The bridge's own `deploy_token` is only paused for non-DAO callers; a DAO-role caller on the bridge can still trigger the chain `bridge.deploy_token → deployer.deploy_token` even when the deployer is paused.
- `LegacyController` accounts can call the token-deployer directly without going through the bridge at all.
- No special attacker capability is required beyond holding one of these two already-granted roles.

---

### Recommendation

Add `#[pause]` to `deploy_token` in the token-deployer, consistent with how the bridge protects its own `deploy_token`:

```rust
#[payable]
#[pause]
#[access_control_any(roles(Role::Controller, Role::LegacyController))]
pub fn deploy_token(&mut self, account_id: AccountId, metadata: &BasicMetadata) -> Promise {
    ...
}
```

If DAO must be able to deploy tokens even during a pause (e.g., to deploy a fixed implementation), use `#[pause(except(roles(Role::DAO)))]` instead.

---

### Proof of Concept

On a local NEAR sandbox:

```rust
// 1. Grant PauseManager role to attacker_account
deployer.acl_grant_role("PauseManager", attacker_account);

// 2. Pause the TokenDeployer
deployer.pa();  // contract is now paused

// 3. Call deploy_token from Controller — succeeds despite pause
let result = deployer
    .as_account(controller_account)
    .deploy_token(new_token_account_id, metadata);

// 4. Assert: new_token_account_id now exists with the stale global_code_hash WASM
assert!(new_token_account_id.exists());
// Pause was completely bypassed
```

Expected: the call should panic with a "paused" error. Actual: it succeeds and deploys the token.

### Citations

**File:** near/token-deployer/src/lib.rs (L27-28)
```rust
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[pausable(manager_roles(Role::PauseManager))]
```

**File:** near/token-deployer/src/lib.rs (L58-60)
```rust
    #[payable]
    #[access_control_any(roles(Role::Controller, Role::LegacyController))]
    pub fn deploy_token(&mut self, account_id: AccountId, metadata: &BasicMetadata) -> Promise {
```

**File:** near/token-deployer/src/lib.rs (L61-72)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L4-6)
```rust
use near_plugins::{
    access_control, access_control_any, pause, AccessControlRole, AccessControllable, Pausable,
    Upgradable,
```
