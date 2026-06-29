### Title
Removed Trusted Relayer's Accrued Fees Become Permanently Locked - (`near/omni-bridge/src/lib.rs`)

### Summary
When a trusted relayer is forcibly removed via `reject_relayer_application` (or voluntarily resigns via `resign_trusted_relayer`) after having signed pending outbound transfers — thereby embedding themselves as `fee_recipient` in the destination-chain finalization event — the accrued fees for those transfers become permanently locked in the bridge contract. The removed relayer cannot call `claim_fee` (blocked by the `#[trusted_relayer]` guard), and no other account can claim the fee either (blocked by the `OnlyFeeRecipientCanClaim` check). The result is permanent freezing of user-paid fee funds held in escrow.

---

### Finding Description

The `claim_fee` entry point is decorated with `#[trusted_relayer]`: [1](#0-0) 

Inside `claim_fee_callback`, the contract enforces that only the exact `fee_recipient` embedded in the proof can collect: [2](#0-1) 

The `fee_recipient` is set at `sign_transfer` time on NEAR, propagated into the MPC-signed transaction, and recorded on the destination chain as part of the finalization event. It is therefore immutable once the transfer is finalized on the foreign chain.

The DAO can forcibly remove an active trusted relayer using `reject_relayer_application`, as demonstrated by the integration test `test_dao_revoke_active_relayer`: [3](#0-2) 

A relayer can also voluntarily resign via `resign_trusted_relayer`, which immediately strips trusted status: [4](#0-3) 

After either removal path, the removed relayer's account is no longer trusted. Any `pending_transfers` where that relayer is the `fee_recipient` remain in the contract's `pending_transfers` map with no recovery path: [5](#0-4) 

The fee tokens (which are part of the user's locked bridge amount) can never be released: the removed relayer is blocked by `#[trusted_relayer]`, and any other trusted relayer is blocked by `OnlyFeeRecipientCanClaim`.

---

### Impact Explanation

The fee is carved out of the user's bridged token amount and held in the bridge's escrow (`locked_tokens` for non-deployed tokens, or the bridge's minting authority for deployed tokens). When the fee cannot be claimed, those tokens are permanently frozen inside the bridge contract — matching the **Critical** impact category of "permanent freezing of bridged funds." [6](#0-5) 

---

### Likelihood Explanation

This occurs every time the DAO forcibly removes a relayer (a slashing-equivalent action) while that relayer has signed transfers awaiting finalization on a foreign chain. Given that cross-chain finalization can take minutes to hours (light-client or Wormhole latency), there is a meaningful window between `sign_transfer` and `claim_fee` during which removal can occur. Likelihood is **High** for the forced-removal case.

---

### Recommendation

On removal of a trusted relayer (both `reject_relayer_application` and `resign_trusted_relayer`), either:
1. Scan and reassign `fee_recipient` for all pending transfers owned by the removed relayer to a protocol-controlled account (e.g., DAO treasury), or
2. Remove the `#[trusted_relayer]` guard from `claim_fee` and instead rely solely on the `fee_recipient == predecessor_account_id` check, so that a removed relayer can still collect fees they legitimately earned before removal. This mirrors the recommendation in the reference report (allow the removed party to collect, or redirect to a chosen account).

---

### Proof of Concept

1. Relayer `R` is a trusted relayer with stake deposited.
2. User initiates a NEAR→ETH transfer with a fee of 1000 tokens; `R` calls `sign_transfer` naming itself as `fee_recipient`. The MPC-signed transaction is submitted to Ethereum and finalized — the Ethereum event records `fee_recipient = R`.
3. DAO calls `reject_relayer_application(R)` (works on active relayers per `test_dao_revoke_active_relayer`). `R`'s stake is slashed to the DAO; `R` is no longer trusted.
4. `R` attempts `claim_fee` with the Ethereum finalization proof → **panics** at `#[trusted_relayer]` guard.
5. Any other trusted relayer attempts `claim_fee` with the same proof → **panics** at `require!(fee_recipient == *predecessor_account_id, BridgeError::OnlyFeeRecipientCanClaim)`.
6. The 1000-token fee is permanently locked in the bridge contract with no recovery mechanism. [7](#0-6) [8](#0-7)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L1122-1133)
```rust
        let denormalized_amount = Self::denormalize_amount(
            fin_transfer.amount.0,
            self.token_decimals
                .get(&token_address)
                .near_expect(BridgeError::TokenDecimalsNotFound),
        );
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```

**File:** near/omni-tests/src/relayer_staking.rs (L338-366)
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

        // Verify stake is removed
        let stake: Option<U128> = env
            .bridge_contract
            .view("get_relayer_stake")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(stake.is_none());
```

**File:** near/omni-tests/src/relayer_staking.rs (L467-491)
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

        Ok(())
    }
```
