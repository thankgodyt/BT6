### Title
Trusted Relayer Can Immediately Resign to Front-Run DAO Stake Slashing — (`near/omni-bridge/src/lib.rs`, `#[trusted_relayer]` macro)

### Summary

The `resign_trusted_relayer` function imposes no cooldown or delay before returning a trusted relayer's full stake. A malicious trusted relayer who observes a pending DAO `reject_relayer_application` transaction (which slashes the stake) can front-run it with `resign_trusted_relayer`, recovering their full stake and completely nullifying the economic penalty mechanism.

### Finding Description

The bridge implements a two-phase relayer staking system:

1. **Entry (with delay):** `apply_for_trusted_relayer` locks a stake deposit and enforces a `waiting_period_ns` (default 604,800,000,000,000 ns = 7 days) before the relayer becomes trusted. [1](#0-0) 

2. **Exit (no delay):** `resign_trusted_relayer` immediately returns the full stake and removes trusted status with no waiting period. [2](#0-1) 

3. **DAO slash (stake forfeited):** `reject_relayer_application` removes trusted status and transfers the stake to the DAO account instead of returning it to the relayer. [3](#0-2) 

The asymmetry is the root cause: entry is time-locked, but exit is instant. The `#[trusted_relayer]` macro applied to the `Contract` impl block generates these functions. [4](#0-3) 

The default waiting period confirms the protocol designers intended a meaningful delay to prevent gaming, but this delay only applies to entry, not exit. [5](#0-4) 

### Impact Explanation

The stake is the sole economic deterrent against relayer misbehavior (e.g., submitting fraudulent or replayed proofs to `fin_transfer`, or colluding to sign invalid outbound transfers via `sign_transfer`). [6](#0-5) 

If a malicious trusted relayer can always recover their stake before the DAO can slash it, the economic security guarantee of the relayer staking system is completely nullified. The DAO's `reject_relayer_application` slash path becomes unreachable in practice against a monitoring attacker. This is a bypass of the protocol's authorization/penalty enforcement mechanism.

### Likelihood Explanation

NEAR transactions are publicly visible in the mempool. A relayer monitoring for a DAO governance transaction targeting their account can trivially submit `resign_trusted_relayer` with higher priority (or simply in the same block, since NEAR block times are ~1 second). No special capability beyond being a trusted relayer is required.

### Recommendation

Introduce a mandatory cooldown period on `resign_trusted_relayer` that is at least as long as the DAO's governance reaction time. During this cooldown, the stake should remain locked and slashable. Alternatively, record a "resignation signal" timestamp and only release the stake after the cooldown elapses, mirroring the entry waiting period design.

### Proof of Concept

1. Attacker applies for trusted relayer status, deposits 1,000 NEAR stake, waits 7 days for `waiting_period_ns` to elapse. [7](#0-6) 
2. Attacker is now a trusted relayer and begins submitting proofs via `fin_transfer` / `sign_transfer`.
3. DAO detects misbehavior and submits a `reject_relayer_application` transaction.
4. Attacker observes the pending DAO transaction and immediately calls `resign_trusted_relayer` in the same or prior block.
5. `resign_trusted_relayer` executes first: full 1,000 NEAR stake is returned to the attacker. [8](#0-7) 
6. DAO's `reject_relayer_application` now finds no active relayer record and either fails or has no stake to slash.
7. Attacker re-applies immediately with the recovered stake and repeats the cycle with zero net cost.

### Citations

**File:** near/omni-tests/src/relayer_staking.rs (L87-98)
```rust
        // Set a short waiting period for testing (1 second in nanoseconds)

        env.bridge_contract
            .call("set_relayer_config")
            .args_json(json!({
                "stake_required": U128(1_000 * 10u128.pow(24)),
                "waiting_period_ns": U64(1_000_000_000),
            }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
```

**File:** near/omni-tests/src/relayer_staking.rs (L315-325)
```rust
        // Apply
        applicant
            .call(env.bridge_contract.id(), "apply_for_trusted_relayer")
            .deposit(NearToken::from_near(1000))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        // Wait past activation period
        env.worker.fast_forward(100).await?;
```

**File:** near/omni-tests/src/relayer_staking.rs (L338-357)
```rust
        // Resign
        applicant
            .call(env.bridge_contract.id(), "resign_trusted_relayer")
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        // Verify relayer is no longer trusted
        let is_trusted: bool = env
            .bridge_contract
            .view("is_trusted_relayer")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(!is_trusted);

        // Verify NEAR was returned
        let balance_after_resign = applicant.view_account().await?.balance;
        assert!(balance_after_resign.as_yoctonear() > balance_before_resign.as_yoctonear());
```

**File:** near/omni-tests/src/relayer_staking.rs (L467-488)
```rust
        // DAO revokes active relayer
        let dao_balance_before = dao_account.view_account().await?.balance;
        dao_account
            .call(env.bridge_contract.id(), "reject_relayer_application")
            .args_json(json!({"account_id": applicant.id()}))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        // Verify relayer is no longer trusted
        let is_trusted: bool = env
            .bridge_contract
            .view("is_trusted_relayer")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(!is_trusted);

        // Verify stake was transferred to DAO account
        let dao_balance_after = dao_account.view_account().await?.balance;
        assert!(dao_balance_after.as_yoctonear() > dao_balance_before.as_yoctonear());
```

**File:** near/omni-tests/src/relayer_staking.rs (L507-509)
```rust
        let default_stake = (1_000u128 * 10u128.pow(24)).to_string();
        assert_eq!(config["stake_required"], json!(default_stake));
        assert_eq!(config["waiting_period_ns"], json!(U64(604_800_000_000_000)));
```

**File:** near/omni-bridge/src/lib.rs (L245-249)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

**File:** near/omni-bridge/src/lib.rs (L670-696)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
        require!(
            args.storage_deposit_actions.len() <= 3,
            BridgeError::InvalidStorageAccountsLen.as_ref()
        );
        let mut main_promise = self.verify_proof(args.chain_kind, args.prover_args);

        let mut attached_deposit = env::attached_deposit();

        for action in &args.storage_deposit_actions {
            main_promise =
                main_promise.and(Self::check_or_pay_ft_storage(action, &mut attached_deposit));
        }

        main_promise.then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(attached_deposit)
                .with_static_gas(FIN_TRANSFER_CALLBACK_GAS)
                .fin_transfer_callback(
                    &args.storage_deposit_actions,
                    env::predecessor_account_id(),
                ),
        )
    }
```
