### Title
Trusted Relayer Can Front-Run DAO Slash by Immediately Resigning — (`near/omni-bridge/src/lib.rs`)

### Summary

The NEAR Omni Bridge implements a relayer staking system via the `#[trusted_relayer]` macro. A trusted relayer can call `resign_trusted_relayer` at any time to immediately recover their full stake. There is no exit lockup/cooldown period enforced on resignation. The DAO's only slashing mechanism (`reject_relayer_application`) requires a separate on-chain transaction. A malicious trusted relayer who has misbehaved can observe a pending DAO slash transaction and front-run it by calling `resign_trusted_relayer` first, recovering their full stake and escaping the penalty entirely.

### Finding Description

The contract applies the `#[trusted_relayer]` macro with the following configuration:

```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
``` [1](#0-0) 

This macro generates the relayer lifecycle functions including `apply_for_trusted_relayer`, `resign_trusted_relayer`, and `reject_relayer_application`. The activation path enforces a `waiting_period_ns` (default: 604,800,000,000,000 ns = 7 days) before an applicant becomes trusted: [2](#0-1) 

However, the **exit path** (`resign_trusted_relayer`) has no corresponding lockup. The integration test confirms that resignation is immediate and returns the full stake in the same transaction: [3](#0-2) 

The DAO's slash path (`reject_relayer_application`) transfers the stake to the DAO caller: [4](#0-3) 

Because NEAR is a sequential, single-threaded execution environment, a malicious relayer who monitors the mempool (or simply acts before the DAO can react) can call `resign_trusted_relayer` before the DAO's `reject_relayer_application` is included in a block. Once the relayer has resigned and the stake is returned, the DAO's slash call will find no stake to seize and will either fail or be a no-op.

### Impact Explanation

The stake is the sole economic deterrent against relayer misbehavior. If a malicious trusted relayer can always escape slashing by resigning first, the staking mechanism provides no real security guarantee. The DAO loses the expected slashed stake (economic loss to the protocol), and the malicious relayer retains their full deposit (economic gain). The relayer can then re-apply and repeat the cycle. This is a direct bypass of the protocol's slash/accountability mechanism.

### Likelihood Explanation

A malicious relayer has a strong financial incentive to front-run the slash: they recover 1,000 NEAR (the default `stake_required`) instead of losing it. NEAR's block time is approximately 1 second, and the DAO's slash requires a governance decision process that takes time to coordinate and submit. The malicious relayer, monitoring their own account, can react faster than any off-chain governance process.

### Recommendation

Introduce an exit lockup period (`resign_lockup_ns`) that must be strictly greater than the time required for the DAO to detect misbehavior and execute a slash. The `resign_trusted_relayer` call should record a resignation timestamp and only release the stake after the lockup has elapsed. During the lockup window, the DAO must still be able to slash the resigning relayer's escrowed stake. This mirrors the fix applied in the Audius protocol (PR #657), where `decreaseStakeLockupDuration` was enforced to be greater than `votingPeriod + executionDelay`.

### Proof of Concept

1. Malicious relayer calls `apply_for_trusted_relayer` with 1,000 NEAR stake.
2. Waits for `waiting_period_ns` (7 days) to elapse; becomes a trusted relayer.
3. Relayer misbehaves (e.g., censors transfers, front-runs users).
4. DAO detects misbehavior and prepares a `reject_relayer_application` transaction.
5. Malicious relayer observes the pending DAO action and immediately calls `resign_trusted_relayer`.
6. `resign_trusted_relayer` executes first (no lockup), returning the full 1,000 NEAR stake to the relayer.
7. DAO's `reject_relayer_application` now finds no active relayer record and cannot seize any stake.
8. Malicious relayer has escaped the slash and retains their full 1,000 NEAR. [5](#0-4) [1](#0-0)

### Citations

**File:** near/omni-bridge/src/lib.rs (L245-249)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

**File:** near/omni-tests/src/relayer_staking.rs (L293-368)
```rust
    #[rstest]
    #[tokio::test]
    async fn test_resign_relayer(
        #[from(locker_wasm)] locker: Vec<u8>,
        #[from(mock_prover_wasm)] prover: Vec<u8>,
    ) -> anyhow::Result<()> {
        let env = TestEnv::new(locker, prover).await?;

        // Set a short waiting period
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

        let applicant = env.create_funded_account("applicant", 2000).await?;

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

        // Verify relayer is now trusted
        let is_trusted: bool = env
            .bridge_contract
            .view("is_trusted_relayer")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(is_trusted);

        let balance_before_resign = applicant.view_account().await?.balance;

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

        // Verify stake is removed
        let stake: Option<U128> = env
            .bridge_contract
            .view("get_relayer_stake")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(stake.is_none());

        Ok(())
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
