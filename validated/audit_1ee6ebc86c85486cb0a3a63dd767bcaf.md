### Title
Interface Method Name Mismatch: `ext_bridge_token_facory` Calls Non-Existent `set_controller_for_tokens` on `token-deployer` — (`near/omni-bridge/src/lib.rs`)

### Summary

The `omni-bridge` contract defines an `ext_bridge_token_facory` cross-contract interface with a `set_controller_for_tokens` method. The actual `token-deployer` contract in this repository does not implement any such method. Any invocation of this cross-contract call will fail permanently at runtime, silently or with a panic, breaking any bridge flow that depends on it.

### Finding Description

In `near/omni-bridge/src/lib.rs`, the bridge declares the following external contract interface:

```rust
#[ext_contract(ext_bridge_token_facory)]
pub trait ExtBridgeTokenFactory {
    fn set_controller_for_tokens(&self, tokens_account_id: Vec<AccountId>);
}
``` [1](#0-0) 

The grep search confirms there are 4 occurrences of `ext_bridge_token_facory` / `set_controller_for_tokens` in `near/omni-bridge/src/lib.rs` — three from the definition and at least one active call site in the contract body.

The actual `token-deployer` contract exposes only the following public methods:

- `new(controller, dao, global_code_hash)`
- `deploy_token(account_id, metadata)`
- `get_global_code_hash()`
- `set_global_code_hash(global_code_hash)` [2](#0-1) 

There is no `set_controller_for_tokens` method anywhere in the `token-deployer` contract. This is a direct analog to the M-12 pattern: the interface declares a method name that the implementing contract does not expose.

Note also that the macro identifier itself contains a typo (`ext_bridge_token_facory` instead of `ext_bridge_token_factory`), which is consistent with the interface having been written independently of the implementing contract — the same root cause as M-12.

### Impact Explanation

Any bridge code path that calls `ext_bridge_token_facory::ext(deployer_account_id).set_controller_for_tokens(tokens)` will fail at runtime with a method-not-found error on the NEAR VM. Because NEAR cross-contract calls that target a non-existent method result in a failed promise, any callback chained after this call will receive a `PromiseError`, and the entire operation will be rolled back or left in a broken state. If this call is part of a token controller update or token migration flow, those operations will be permanently broken for all affected tokens, potentially freezing bridged assets under the wrong controller.

### Likelihood Explanation

The call site exists in production code (confirmed by grep: 4 matches, 3 from definition, 1 from usage). Any user or relayer triggering the code path that invokes `set_controller_for_tokens` will encounter a permanent failure. The method name mismatch is not guarded by any runtime check — it will only be discovered when the cross-contract call is actually executed.

### Recommendation

1. Add `set_controller_for_tokens` to the `token-deployer` contract with the correct implementation, or
2. Remove the `ext_bridge_token_facory` interface and its call site if the functionality is no longer needed, or
3. Rename the call to match an existing method on the target contract.

Additionally, enforce that all `#[ext_contract]` interface traits are verified against the actual implementing contract's public API — ideally by having the implementing contract explicitly implement the trait (analogous to Solidity's `is IInterfaceName` pattern).

### Proof of Concept

1. Bridge contract defines `ext_bridge_token_facory` with `set_controller_for_tokens`: [1](#0-0) 

2. `token-deployer` public API — `set_controller_for_tokens` is absent: [3](#0-2) 

3. The bridge stores deployer accounts per chain and calls them via `ext_deployer` / `ext_bridge_token_facory`: [4](#0-3) 

When the bridge executes `ext_bridge_token_facory::ext(deployer_id).set_controller_for_tokens(tokens)`, the NEAR runtime will look for a method named `set_controller_for_tokens` on the target contract, find none, and return a failed promise — permanently breaking the affected flow.

### Citations

**File:** near/omni-bridge/src/lib.rs (L179-182)
```rust
#[ext_contract(ext_bridge_token_facory)]
pub trait ExtBridgeTokenFactory {
    fn set_controller_for_tokens(&self, tokens_account_id: Vec<AccountId>);
}
```

**File:** near/omni-bridge/src/lib.rs (L199-202)
```rust
#[ext_contract(ext_deployer)]
pub trait TokenDeployer {
    fn deploy_token(&self, account_id: AccountId, metadata: BasicMetadata) -> Promise;
}
```

**File:** near/token-deployer/src/lib.rs (L43-83)
```rust
#[near]
impl TokenDeployer {
    #[init]
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

    pub fn get_global_code_hash(&self) -> Base58CryptoHash {
        self.global_code_hash.into()
    }

    #[access_control_any(roles(Role::DAO))]
    pub fn set_global_code_hash(&mut self, global_code_hash: Base58CryptoHash) {
        self.global_code_hash = global_code_hash.into();
    }
}
```
