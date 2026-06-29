### Title
Relayer Applicant Cannot Cancel Pending Application and Recover Staked NEAR Without DAO Cooperation - (File: `near/omni-bridge/src/lib.rs` / relayer staking module)

---

### Summary

The relayer staking system exposes `apply_for_trusted_relayer` and `resign_trusted_relayer`, but provides no self-cancel path for a pending applicant. During the mandatory waiting period, an applicant's staked NEAR is locked in the bridge contract with no unilateral exit. The only privileged exit — `reject_relayer_application` — is DAO-only and permanently confiscates the stake to the DAO rather than returning it to the applicant.

---

### Finding Description

A relayer applicant calls `apply_for_trusted_relayer` and deposits the required stake (default 1,000 NEAR). The application enters a pending state governed by a `waiting_period_ns` (default 604,800,000,000,000 ns = 7 days). During this window:

1. **`resign_trusted_relayer` is blocked for pending applicants.** The test `test_resign_non_active_relayer_fails` explicitly confirms the call reverts and the application remains intact. [1](#0-0) 

2. **No `cancel_relayer_application` or equivalent self-exit function exists.** There is no on-chain path for the applicant to withdraw their pending application and recover their stake.

3. **The only exit is DAO-controlled `reject_relayer_application`, which confiscates the stake to the DAO.** The test `test_dao_reject_application` explicitly asserts that the applicant does not receive the stake back and that the DAO account balance increases. [2](#0-1) 

The default configuration requires 1,000 NEAR stake and a 7-day waiting period. [3](#0-2) 

---

### Impact Explanation

A relayer applicant who deposits 1,000 NEAR and later wishes to withdraw their application during the 7-day waiting period has no on-chain mechanism to do so. Their staked NEAR is held in escrow by the bridge contract with no self-exit path. If the DAO exercises `reject_relayer_application`, the applicant's entire stake is permanently transferred to the DAO — not returned. This constitutes permanent loss of the applicant's own NEAR tokens through escrow mis-accounting: the contract accepts a deposit under conditions that provide no guaranteed return path to the depositor.

---

### Likelihood Explanation

Any account can call `apply_for_trusted_relayer` and deposit stake. The 7-day waiting period is the default and applies to all applicants. The absence of a cancel function is a structural gap, not a configuration edge case. Any applicant who changes their mind, encounters an emergency, or is rejected by the DAO loses their stake with no recourse. [4](#0-3) 

---

### Recommendation

Add a `cancel_relayer_application` function callable only by the applicant themselves (i.e., `env::predecessor_account_id()` must match the applicant), restricted to the pending (pre-activation) state. This function should remove the application record and return the full staked NEAR to the applicant. The `resign_trusted_relayer` path (for active relayers) already demonstrates the correct pattern for stake return. [5](#0-4) 

---

### Proof of Concept

1. Applicant calls `apply_for_trusted_relayer` with 1,000 NEAR deposit. Application is recorded; stake is held by the bridge contract.
2. Applicant calls `resign_trusted_relayer` before the waiting period elapses → **reverts**. Application still exists; stake still locked.
3. No `cancel_relayer_application` call exists on the contract.
4. DAO calls `reject_relayer_application(applicant)` → application removed, 1,000 NEAR transferred to DAO account, applicant balance unchanged (net loss of ~1,000 NEAR). [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-tests/src/relayer_staking.rs (L100-110)
```rust
        let applicant = env.create_funded_account("applicant", 2000).await?;

        // Apply
        let result = applicant
            .call(env.bridge_contract.id(), "apply_for_trusted_relayer")
            .deposit(NearToken::from_near(1000))
            .max_gas()
            .transact()
            .await?;
        result.into_result()?;

```

**File:** near/omni-tests/src/relayer_staking.rs (L257-290)
```rust
        // DAO rejects
        let dao_balance_before_reject = dao_account.view_account().await?.balance;
        dao_account
            .call(env.bridge_contract.id(), "reject_relayer_application")
            .args_json(json!({"account_id": applicant.id()}))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        // Verify application is removed
        let application: Option<serde_json::Value> = env
            .bridge_contract
            .view("get_relayer_application")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(application.is_none());

        // Verify stake was NOT returned to applicant (goes to DAO/relayer manager).
        // The applicant's balance may increase slightly due to protocol rewards,
        // so we check that the bulk of the stake (1000 NEAR) was not refunded.
        let balance_after_reject = applicant.view_account().await?.balance;
        assert!(
            balance_before.as_yoctonear() - balance_after_reject.as_yoctonear()
                >= NearToken::from_near(999).as_yoctonear(),
            "Applicant should not have received the stake back"
        );

        // Verify stake was transferred to DAO account
        let dao_balance_after_reject = dao_account.view_account().await?.balance;
        assert!(dao_balance_after_reject.as_yoctonear() > dao_balance_before_reject.as_yoctonear());

        Ok(())
```

**File:** near/omni-tests/src/relayer_staking.rs (L336-368)
```rust
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

**File:** near/omni-tests/src/relayer_staking.rs (L371-409)
```rust
    #[rstest]
    #[tokio::test]
    async fn test_resign_non_active_relayer_fails(
        #[from(locker_wasm)] locker: Vec<u8>,
        #[from(mock_prover_wasm)] prover: Vec<u8>,
    ) -> anyhow::Result<()> {
        let env = TestEnv::new(locker, prover).await?;

        let applicant = env.create_funded_account("applicant", 2000).await?;

        // Apply
        applicant
            .call(env.bridge_contract.id(), "apply_for_trusted_relayer")
            .deposit(NearToken::from_near(1000))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        // Try to resign before activation (should fail)
        let result = applicant
            .call(env.bridge_contract.id(), "resign_trusted_relayer")
            .max_gas()
            .transact()
            .await?;

        assert!(result.into_result().is_err());

        // Verify the relayer application still exists
        let application: Option<serde_json::Value> = env
            .bridge_contract
            .view("get_relayer_application")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(application.is_some());

        Ok(())
    }
```

**File:** near/omni-tests/src/relayer_staking.rs (L507-509)
```rust
        let default_stake = (1_000u128 * 10u128.pow(24)).to_string();
        assert_eq!(config["stake_required"], json!(default_stake));
        assert_eq!(config["waiting_period_ns"], json!(U64(604_800_000_000_000)));
```
