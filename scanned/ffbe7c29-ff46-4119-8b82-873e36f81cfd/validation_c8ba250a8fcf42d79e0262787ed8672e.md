### Title
Attached NEAR deposit permanently lost in `deploy_token` when proof verification or callback fails — (File: `near/omni-bridge/src/lib.rs`)

### Summary

`deploy_token` is a `#[payable]` public function callable by any unprivileged user. It accepts a NEAR storage deposit but has **no refund path** if the multi-step promise chain fails at any point. By contrast, the structurally similar `bind_token` function explicitly appends a `bind_token_refund` callback to return unused funds. The missing refund in `deploy_token` causes the caller's entire attached deposit to be permanently absorbed into the bridge contract's balance.

### Finding Description

`deploy_token` builds a two-step promise chain:

```
verify_proof  →  deploy_token_callback (NO_DEPOSIT)
``` [1](#0-0) 

The user's deposit (`env::attached_deposit()`) is captured at call time and forwarded only as a **Borsh-serialised parameter** to `deploy_token_callback`; the callback itself is scheduled with `NO_DEPOSIT`. This means the full deposit sits in the bridge contract's balance throughout the chain.

`deploy_token_callback` panics (via `env::panic_str`) in three reachable failure modes:

1. **Proof verification fails** — prover returns `Err` or a non-`LogMetadata` variant.
2. **Unknown factory** — `self.factories.get(&chain) != Some(metadata.emitter_address)`.
3. **Insufficient deposit** — inside `deploy_token_internal`, `attached_deposit < required_deposit` (storage + `NEP141_DEPOSIT`). [2](#0-1) 

In NEAR, a panicking callback rolls back its own state changes but does **not** return the NEAR that was deposited in the original call. The deposit remains in the contract's balance with no mechanism to retrieve it.

Compare to `bind_token`, which appends a third promise — `bind_token_refund` — that always runs and returns the remaining deposit to the caller: [3](#0-2) [4](#0-3) 

`deploy_token` has no equivalent third step.

### Impact Explanation

Any NEAR attached to a failing `deploy_token` call is permanently locked in the bridge contract. The user has no recovery path: `storage_withdraw` only returns funds from the user's registered storage balance, not from the contract's general balance. The deposit required for token deployment is non-trivial (storage bytes for multiple maps + `NEP141_DEPOSIT`), so real monetary loss occurs on every failed call.

### Likelihood Explanation

`deploy_token` has no role restriction — any account can call it when the contract is unpaused. Realistic failure triggers include:

- A factory address is removed between proof creation and submission.
- A race condition where two callers submit proofs for the same token; the second call hits `BridgeError::TokenExists` inside `deploy_token_internal`.
- A proof for a chain whose factory was never registered.
- Metadata so large that the minimum-required deposit estimate is insufficient (the test suite explicitly exercises this case). [5](#0-4) 

### Recommendation

Mirror the `bind_token` pattern: append a refund callback that always executes and returns any unused deposit to the original caller.

```rust
pub fn deploy_token(&mut self, #[serializer(borsh)] args: DeployTokenArgs) -> Promise {
    self.verify_proof(args.chain_kind, args.prover_args)
        .then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(NO_DEPOSIT)
                .with_static_gas(DEPLOY_TOKEN_CALLBACK_GAS)
                .deploy_token_callback(near_sdk::env::attached_deposit()),
        )
        .then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(DEPLOY_TOKEN_REFUND_GAS)
                .deploy_token_refund(env::predecessor_account_id()),
        )
}
```

`deploy_token_refund` should follow the same logic as `bind_token_refund`: on success, refund the remainder returned by the callback; on failure, refund the full attached deposit.

### Proof of Concept

1. Alice calls `deploy_token` with 5 NEAR attached and a proof for token `T` on chain `Eth`.
2. `verify_proof` succeeds and returns `ProverResult::LogMetadata`.
3. Concurrently, Bob's identical call is processed first; `T` is now registered.
4. Alice's `deploy_token_callback` reaches `deploy_token_internal`, which panics at `require!(self.deployed_tokens.insert(&token_id), BridgeError::TokenExists)`.
5. The callback panic rolls back state changes but Alice's 5 NEAR remains in the bridge contract's balance.
6. Alice has no function to call to recover her deposit. [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1136-1145)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn deploy_token(&mut self, #[serializer(borsh)] args: DeployTokenArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(NO_DEPOSIT)
                .with_static_gas(DEPLOY_TOKEN_CALLBACK_GAS)
                .deploy_token_callback(near_sdk::env::attached_deposit()),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1147-1175)
```rust
    #[private]
    pub fn deploy_token_callback(
        &mut self,
        attached_deposit: NearToken,
        #[callback_result]
        #[serializer(borsh)]
        call_result: Result<ProverResult, PromiseError>,
    ) -> Promise {
        let Ok(ProverResult::LogMetadata(metadata)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str());
        };

        let chain = metadata.emitter_address.get_chain();
        require!(
            self.factories.get(&chain) == Some(metadata.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        self.deploy_token_internal(
            chain,
            &metadata.token_address,
            BasicMetadata {
                name: metadata.name,
                symbol: metadata.symbol,
                decimals: metadata.decimals,
            },
            attached_deposit,
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1223-1238)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn bind_token(&mut self, #[serializer(borsh)] args: BindTokenArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args)
            .then(
                Self::ext(env::current_account_id())
                    .with_attached_deposit(NO_DEPOSIT)
                    .with_static_gas(BIND_TOKEN_CALLBACK_GAS)
                    .bind_token_callback(near_sdk::env::attached_deposit()),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_attached_deposit(env::attached_deposit())
                    .with_static_gas(BIND_TOKEN_REFUND_GAS)
                    .bind_token_refund(near_sdk::env::predecessor_account_id()),
            )
```

**File:** near/omni-bridge/src/lib.rs (L1303-1312)
```rust
    #[private]
    #[payable]
    pub fn bind_token_refund(
        &mut self,
        predecessor_account_id: AccountId,
        #[callback_result] call_result: Result<NearToken, PromiseError>,
    ) {
        let refund_amount = call_result.unwrap_or_else(|_| env::attached_deposit());
        Self::refund(predecessor_account_id, refund_amount);
    }
```

**File:** near/omni-bridge/src/lib.rs (L2421-2435)
```rust
        require!(
            self.deployed_tokens.insert(&token_id),
            BridgeError::TokenExists.as_ref()
        );
        self.deployed_tokens_v2
            .insert(&token_id, &token_address.get_chain());

        let required_deposit = env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
            .saturating_add(NEP141_DEPOSIT);

        require!(
            attached_deposit >= required_deposit,
            BridgeError::InsufficientStorageDeposit.as_ref()
        );
```
