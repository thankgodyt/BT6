### Title
Full Access Key Not Revoked on Controller Change in OmniToken — (File: near/omni-token/src/lib.rs)

### Summary

`OmniToken` exposes `attach_full_access_key`, callable by the current controller, which permanently adds a NEAR full-access key to the token contract account. When the controller is subsequently changed via `update_tokens_controller` / `set_controller_for_tokens`, no mechanism removes previously attached full-access keys. The holder of any such key retains unrestricted, controller-bypassing access to the token account — including the ability to deploy arbitrary code, mint or burn tokens, and delete the account — even after the controller has changed.

### Finding Description

**Root cause — `attach_full_access_key` with no key lifecycle management:**

`OmniToken.attach_full_access_key` (line 82–85) is a public, controller-gated function that calls `Promise::new(env::current_account_id()).add_full_access_key(public_key)`: [1](#0-0) 

The function is gated only by `assert_controller()`, which checks `env::predecessor_account_id() == self.controller`: [2](#0-1) 

This is the intended migration path: the controller (bridge contract) attaches a full-access key so that the token account can self-call `migrate`. The integration test confirms this exact flow — the locker contract (controller) calls `attach_full_access_key` with a freshly generated keypair, then uses that key to call `migrate`: [3](#0-2) 

**Controller change does not revoke keys:**

The bridge contract exposes `update_tokens_controller`, which calls `set_controller_for_tokens` on the token deployer factory to update `self.controller` in each token: [4](#0-3) 

Neither `update_tokens_controller` nor any downstream call issues a `Promise::delete_key` or `Promise::delete_account` to revoke previously attached full-access keys on the token accounts. The `OmniToken` contract has no `revoke_key` or `remove_full_access_key` method at all.

**Exploit flow:**

1. Controller A (current bridge contract or DAO) calls `attach_full_access_key(pk_A)` on an `OmniToken` instance — e.g., for a migration. The private key `sk_A` is held by a human operator or the old bridge deployment.
2. The DAO calls `update_tokens_controller` to change the controller to Controller B (new bridge contract).
3. `pk_A` is **not removed** from the token account's key set.
4. The holder of `sk_A` now has a NEAR full-access key on the token account. They can:
   - Deploy arbitrary new contract code to the token account (bypassing the new controller entirely).
   - Directly call `mint` / `burn` on the token account using the new code.
   - Delete the token account, permanently freezing all bridged funds.
   - Add additional full-access keys, locking out the new controller permanently.

### Impact Explanation

**Critical.** A full-access key on a NEAR account is the highest possible privilege level — it supersedes all contract-level access control. The holder can deploy new WASM, overwrite `self.controller`, and call `mint` to create unbacked bridged tokens or `burn` to destroy user balances. This constitutes unauthorized minting, loss of bridged funds, and permanent freezing — all within the allowed impact scope.

### Likelihood Explanation

The `attach_full_access_key` function is the documented and tested migration mechanism for `OmniToken`. Every token that has undergone a migration has had a full-access key attached. If the controller is subsequently rotated (e.g., bridge upgrade), those keys persist. The migration test in the repository demonstrates this exact pattern. The likelihood is **medium-high**: any token that has been migrated and whose controller has since changed is affected.

### Recommendation

1. **Remove the full-access key after migration completes.** In the `migrate` callback (or at the end of the migration transaction), issue `Promise::new(env::current_account_id()).delete_key(public_key)` to revoke the key immediately after use.
2. **Revoke all non-controller keys on controller change.** When `set_controller_for_tokens` updates `self.controller`, enumerate and delete all full-access keys that are not associated with the new controller.
3. **Track attached keys.** Store the set of attached public keys in contract state so they can be audited and revoked programmatically.

### Proof of Concept

```
# Step 1: Controller (locker) attaches a full-access key to the token
near call <token_account_id> attach_full_access_key \
  '{"public_key": "<pk_attacker>"}' \
  --accountId <locker_contract_id>   # current controller

# Step 2: DAO rotates the controller to a new bridge contract
near call <omni_bridge_id> update_tokens_controller \
  '{"factory_account_id": "<token_deployer_id>", "tokens_accounts_id": ["<token_account_id>"]}' \
  --accountId <dao_account_id>

# Step 3: pk_attacker is still a full-access key on <token_account_id>
# Attacker deploys malicious WASM that mints tokens to themselves
near deploy <token_account_id> malicious_token.wasm \
  --signWithKey <sk_attacker>

# Step 4: Attacker mints unbacked bridged tokens
near call <token_account_id> mint \
  '{"account_id": "<attacker>", "amount": "1000000000000000000000000", "msg": null}' \
  --accountId <token_account_id> \
  --signWithKey <sk_attacker>
```

The key `pk_attacker` remains valid on `<token_account_id>` indefinitely after the controller change, because `update_tokens_controller` only updates the `self.controller` field and never calls `delete_key`. [1](#0-0) [4](#0-3)

### Citations

**File:** near/omni-token/src/lib.rs (L81-85)
```rust
    /// Attach a new full access to the current contract.
    pub fn attach_full_access_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_controller();
        Promise::new(env::current_account_id()).add_full_access_key(public_key)
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

**File:** near/omni-tests/src/omni_token.rs (L993-1019)
```rust
        let sk = near_workspaces::types::SecretKey::from_random(
            near_workspaces::types::KeyType::ED25519,
        );
        let pk = sk.public_key();

        env.locker_contract
            .as_account()
            .call(&env.token_account_id, "attach_full_access_key")
            .args_json(json!({ "public_key": pk }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        let token_account = near_workspaces::Account::from_secret_key(
            env.token_account_id.clone(),
            sk,
            &env.worker,
        );

        token_account
            .call(&env.token_account_id, "migrate")
            .args_json(json!({ "from_version": 3u32 }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
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
