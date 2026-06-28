### Title
Irrevocable `controller` Privilege in `OmniToken` Enables Permanent Unauthorized Minting — (`near/omni-token/src/lib.rs`)

---

### Summary

The `OmniToken` contract stores a single `controller: AccountId` that is set at deployment and can never be changed or revoked. The controller has exclusive authority to `mint` arbitrary token amounts, `burn` tokens, `set_metadata`, `set_withdraw_relayer_address`, and — critically — `attach_full_access_key` to the token contract itself. There is no `set_controller`, `revoke_controller`, or equivalent function anywhere in the contract or its migration path. A compromised or rogue controller account permanently retains all of these privileges with no on-chain remedy.

---

### Finding Description

`OmniToken` is the NEP-141 bridged token contract deployed by `token-deployer` for every token bridged through Omni Bridge. Its state holds a single privileged account:

```rust
// near/omni-token/src/lib.rs:28-32
pub struct OmniToken {
    controller: AccountId,
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
}
``` [1](#0-0) 

The `controller` is set once in `new()` and in `migrate_from_poa()`, and is never modified thereafter:

```rust
// near/omni-token/src/lib.rs:49-79
pub fn new(controller: AccountId, metadata: BasicMetadata) -> Self {
    ...
    Self { controller, ... }
}
``` [2](#0-1) 

All privileged operations are gated by a single check:

```rust
// near/omni-token/src/lib.rs:98-104
fn assert_controller(&self) {
    let caller = env::predecessor_account_id();
    require!(caller == self.controller, TokenError::MissingPermission.as_ref());
}
``` [3](#0-2) 

The functions gated by `assert_controller()` include:

- `mint` — mints arbitrary token amounts to any account [4](#0-3) 
- `burn` — burns tokens from the caller [5](#0-4) 
- `set_withdraw_relayer_address` — redirects legacy withdrawal flows [6](#0-5) 
- `attach_full_access_key` — adds a full-access key to the token contract itself [7](#0-6) 
- `upgrade_and_migrate` — deploys arbitrary new contract code [8](#0-7) 

Neither `lib.rs` nor `migrate.rs` contains any function to update or revoke the `controller`. The grep search across all `near/omni-token/**/*.rs` files confirms there is no `set_controller`, `update_controller`, or `change_controller` function anywhere in the codebase.

The `token-deployer` sets the controller to `env::predecessor_account_id()` at deploy time (the `omni-bridge` contract), and has no mechanism to later change it on any deployed token:

```rust
// near/token-deployer/src/lib.rs:60-68
pub fn deploy_token(&mut self, account_id: AccountId, metadata: &BasicMetadata) -> Promise {
    Promise::new(account_id)
        ...
        .function_call(
            "new".to_string(),
            json!({"controller": env::predecessor_account_id(), "metadata": metadata})...
        )
}
``` [9](#0-8) 

---

### Impact Explanation

If the `omni-bridge` contract (the controller) is ever compromised — through a contract bug that allows arbitrary cross-contract calls, a malicious upgrade pushed through a governance attack, or any other vector — the attacker gains permanent, irrevocable control over every `OmniToken` instance. Specifically, the attacker can:

1. **Mint unbounded tokens** via `mint()`, inflating supply and stealing value from all holders of the bridged asset.
2. **Call `attach_full_access_key`** to add a full-access key to the token contract, enabling arbitrary state manipulation outside the contract's own logic.
3. **Call `upgrade_and_migrate`** to replace the token contract code with arbitrary logic, permanently draining all token balances.

Because there is no `set_controller` function, the legitimate protocol operators have **no on-chain mechanism** to revoke the compromised controller's privileges. Every `OmniToken` deployed through the bridge is permanently affected.

---

### Likelihood Explanation

The `omni-bridge` contract is a complex, upgradeable contract handling cross-chain proofs, MPC signing, relayer staking, and token transfers across multiple chains. Its attack surface is large. The `#[trusted_relayer]` macro, the prover callback chain, and the `fin_transfer` flow all represent potential paths through which a bug could allow an attacker to influence the bridge contract's behavior. The `omni-bridge` contract is also upgradeable via DAO governance, meaning a governance attack is a realistic path to controller compromise. Once compromised, the irrevocability of the controller makes the impact permanent and unrecoverable.

---

### Recommendation

Add a `set_controller` function to `OmniToken` that allows the current controller to transfer the controller role to a new account, and/or allows a designated admin (e.g., the `token-deployer` DAO) to forcibly revoke and replace the controller:

```rust
pub fn set_controller(&mut self, new_controller: AccountId) {
    self.assert_controller();
    self.controller = new_controller;
}
```

Additionally, consider a two-step transfer pattern (propose + accept) to prevent accidental loss of control, and emit an event on controller change for off-chain monitoring.

---

### Proof of Concept

1. The `omni-bridge` contract is the `controller` of all `OmniToken` instances (set via `token-deployer`'s `deploy_token`). [10](#0-9) 
2. Suppose an attacker exploits a bug in `omni-bridge`'s `fin_transfer_callback` or any other cross-contract callback to execute an arbitrary call as the bridge contract.
3. The attacker calls `mint(attacker_account, U128(u128::MAX), None)` on any `OmniToken` instance. The `assert_controller()` check passes because `env::predecessor_account_id()` is the bridge contract. [4](#0-3) 
4. Alternatively, the attacker calls `attach_full_access_key(attacker_public_key)`, gaining a full-access key to the token contract and bypassing all future contract-level access controls. [7](#0-6) 
5. Protocol operators attempt to respond but find there is no `set_controller` function — the controller cannot be changed. The attacker retains permanent minting and upgrade authority over every bridged token. [1](#0-0)

### Citations

**File:** near/omni-token/src/lib.rs (L28-32)
```rust
pub struct OmniToken {
    controller: AccountId,
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
}
```

**File:** near/omni-token/src/lib.rs (L49-79)
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

**File:** near/omni-token/src/lib.rs (L82-85)
```rust
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

**File:** near/omni-token/src/lib.rs (L113-117)
```rust
    pub fn set_withdraw_relayer_address(&mut self, relayer: &AccountId) {
        self.assert_controller();

        env::storage_write(WITHDRAW_RELAYER_ADDRESS, &borsh::to_vec(relayer).unwrap());
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

**File:** near/omni-token/src/lib.rs (L146-151)
```rust
    fn burn(&mut self, amount: U128) {
        self.assert_controller();

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
    }
```

**File:** near/omni-token/src/migrate.rs (L76-107)
```rust
    fn upgrade_and_migrate(&self) {
        self.assert_controller();

        // Receive the code directly from the input to avoid the
        // GAS overhead of deserializing parameters
        let input = env::input()
            .unwrap_or_else(|| env::panic_str(TokenError::NoInput.to_string().as_str()));
        let promise_id = env::promise_batch_create(&env::current_account_id());
        // Allow switching to global contract code when a hash is provided and vice versa.
        if input.len() == 32 {
            let code_hash = input.as_slice().try_into().unwrap_or_else(|_| {
                env::panic_str(TokenError::InvalidCodeHash.to_string().as_str())
            });
            env::promise_batch_action_use_global_contract(promise_id, &code_hash);
        } else {
            // Deploy the contract code.
            env::promise_batch_action_deploy_contract(promise_id, &input);
        }
        // Call promise to migrate the state.
        // Batched together to fail upgrade if migration fails.
        env::promise_batch_action_function_call_weight(
            promise_id,
            "migrate",
            &json!({ "from_version": CURRENT_STATE_VERSION })
                .to_string()
                .into_bytes(),
            NO_DEPOSIT,
            Gas::default(),
            GasWeight::default(),
        );
        env::promise_return(promise_id);
    }
```

**File:** near/token-deployer/src/lib.rs (L60-73)
```rust
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
