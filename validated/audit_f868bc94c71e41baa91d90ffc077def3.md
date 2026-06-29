### Title
Trusted Relayer Status Revocation Permanently Locks Pending Fee Claims After `sign_transfer` - (`near/omni-bridge/src/lib.rs`)

---

### Summary

The `claim_fee` function is gated by `#[trusted_relayer]`. A relayer who calls `sign_transfer` (enabling EVM-side finalization) and then loses trusted status — either by voluntarily resigning via `resign_trusted_relayer` to recover their stake, or by DAO revocation — can never call `claim_fee`. The fee they earned is permanently frozen inside the bridge contract with no alternative recovery path.

---

### Finding Description

The NEAR bridge's NEAR→EVM transfer lifecycle requires a trusted relayer to:
1. Call `sign_transfer` to obtain an MPC signature and authorize the EVM-side release.
2. Submit that signature to the EVM contract, which finalizes the transfer and emits a `FinTransfer` event.
3. Call `claim_fee` with a proof of that EVM event to collect the earned fee.

`sign_transfer` is gated by `#[trusted_relayer]`: [1](#0-0) 

`claim_fee` is **also** gated by `#[trusted_relayer]`: [2](#0-1) 

Inside `claim_fee_callback`, the fee is released only after `remove_transfer_message` is called, which is the only mechanism to finalize the fee accounting: [3](#0-2) 

There is no alternative code path that allows a non-trusted account to claim a fee. If the relayer's trusted status is removed between steps 1 and 3, the transfer message remains in storage indefinitely and the fee tokens remain locked in the bridge contract with no recovery mechanism available to the relayer.

A relayer can lose trusted status in two ways without any compromise:
- **Voluntary resignation**: `resign_trusted_relayer` immediately removes trusted status and returns the stake. A relayer who resigns to recover their stake while a `sign_transfer` is pending on the EVM side loses their fee permanently.
- **DAO revocation**: `reject_relayer_application` (which also handles active relayers per the test `test_dao_revoke_active_relayer`) removes trusted status immediately. [4](#0-3) 

The `transfer_token_as_dao` escape hatch exists but requires manual DAO intervention and bypasses the normal fee accounting, leaving the transfer message in a permanently unresolvable state in storage. [5](#0-4) 

---

### Impact Explanation

A relayer who has legitimately earned a fee by calling `sign_transfer` and enabling EVM finalization cannot recover that fee if their trusted status is removed before `claim_fee` is called. The fee tokens are permanently frozen inside the bridge contract. This matches the allowed impact scope: **permanent freezing of bridged funds**.

---

### Likelihood Explanation

The scenario is realistic and requires no attacker:
- A relayer naturally wants to resign after completing their service to recover their staked NEAR.
- The window between EVM finalization (which can take minutes to hours depending on proof availability) and `claim_fee` is non-trivial.
- A relayer who resigns during this window loses their fee with no recourse.
- DAO revocation of a misbehaving relayer who has pending legitimate fee claims produces the same outcome.

---

### Recommendation

Remove the `#[trusted_relayer]` guard from `claim_fee`, and instead enforce that only the `fee_recipient` embedded in the proof can call it — which is already enforced inside `claim_fee_callback`: [6](#0-5) 

The `fee_recipient == predecessor_account_id` check already prevents unauthorized fee claims. The additional `#[trusted_relayer]` guard on the outer function is redundant for security but creates the liveness hazard described above. Removing it allows any account that was legitimately designated as `fee_recipient` to claim their fee regardless of current trusted status.

---

### Proof of Concept

1. Relayer R applies and becomes a trusted relayer (stake deposited, waiting period elapsed).
2. User initiates a NEAR→EVM transfer via `ft_on_transfer` → `init_transfer`.
3. R calls `sign_transfer` with `fee_recipient = R`. MPC signature is produced and stored.
4. R submits the signature to the EVM bridge; EVM emits `FinTransfer` with `fee_recipient = R`.
5. R calls `resign_trusted_relayer` to recover their staked NEAR. R is immediately no longer trusted.
6. R attempts to call `claim_fee` with the EVM `FinTransfer` proof. The `#[trusted_relayer]` macro rejects the call.
7. The transfer message remains in storage. R's fee is permanently locked in the bridge contract. [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-447)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
```

**File:** near/omni-bridge/src/lib.rs (L1054-1064)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(CLAIM_FEE_CALLBACK_GAS)
                .claim_fee_callback(&env::predecessor_account_id()),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1079-1086)
```rust
        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```

**File:** near/omni-bridge/src/lib.rs (L1511-1529)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn transfer_token_as_dao(
        &mut self,
        token: AccountId,
        amount: U128,
        recipient: AccountId,
        msg: Option<String>,
    ) -> Promise {
        if let Some(msg) = msg {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_CALL_GAS)
                .ft_transfer_call(recipient, amount, None, msg)
        } else {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        }
```

**File:** near/omni-tests/src/relayer_staking.rs (L411-491)
```rust
    #[rstest]
    #[tokio::test]
    async fn test_dao_revoke_active_relayer(
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

        // Create a DAO account and grant it the DAO role
        let dao_account = env.create_funded_account("dao-account", 10).await?;
        env.bridge_contract
            .call("acl_grant_role")
            .args_json(json!({
                "role": "DAO",
                "account_id": dao_account.id(),
            }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

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

        Ok(())
    }
```
