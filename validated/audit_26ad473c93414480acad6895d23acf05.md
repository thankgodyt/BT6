### Title
`claim_fee()` Requires `#[trusted_relayer]` Status That Can Be Removed Before Pending Fast-Transfer Fees Are Settled — (`near/omni-bridge/src/lib.rs`)

### Summary

The `claim_fee` entry point is guarded by the `#[trusted_relayer]` macro. A relayer who executes a fast transfer (fronting tokens to a user) and then resigns (or is revoked) before calling `claim_fee` permanently loses the fees they legitimately earned, because the only code path that pays those fees requires active trusted-relayer status.

### Finding Description

`claim_fee` is the sole mechanism for a relayer to collect fees from transfers where the destination is not NEAR (e.g., NEAR → EVM fast transfers). The function is decorated with `#[trusted_relayer]`, which rejects callers who are not currently in the trusted-relayer set. [1](#0-0) 

`resign_trusted_relayer` (exercised in the integration tests) immediately removes the relayer from the trusted set and returns their stake, with no check for outstanding fee claims stored in `pending_transfers`. [2](#0-1) 

For fast transfers whose destination is NEAR, the fee is automatically routed to the relayer inside `process_fin_transfer_to_near` when anyone calls `fin_transfer`, so no separate `claim_fee` call is needed. However, for fast transfers whose destination is another chain (EVM, Solana, etc.), the fee is only disbursed through `claim_fee` → `claim_fee_callback` → `send_fee_internal`. [3](#0-2) 

`claim_fee_callback` enforces that `fee_recipient == predecessor_account_id`, so no third party can call `claim_fee` on behalf of the resigned relayer either. [4](#0-3) 

The pending transfer record (and the locked tokens it represents) remains in `pending_transfers` indefinitely with no alternative withdrawal path for the relayer. [5](#0-4) 

### Impact Explanation

A relayer who fronted real tokens for a fast transfer to an EVM/Solana destination and then resigned (or was revoked by the DAO) permanently loses the fee portion of those tokens. The fee is locked inside the bridge contract with no reachable code path to recover it. This constitutes a permanent loss of bridged funds for the relayer.

### Likelihood Explanation

Any trusted relayer can trigger this unilaterally by calling `resign_trusted_relayer` after executing a fast transfer but before calling `claim_fee`. The window between fast-transfer execution and fee claim can be hours or days (the second leg must be finalized on the destination chain first). The relayer may resign for legitimate reasons (e.g., wanting to exit) without realizing their pending fees are forfeited. The DAO-revocation path is an admin action and is disqualified, but the self-resignation path is fully user-controlled and realistic.

### Recommendation

Before removing a relayer's trusted status in `resign_trusted_relayer`, the contract should either:
1. Revert if the relayer has any pending fast-transfer fee claims (i.e., entries in `pending_transfers` where `origin_transfer_id` points to a fast transfer owned by this relayer), or
2. Allow a resigned (but formerly trusted) relayer to call `claim_fee` for fast-transfer fees that were earned while they were trusted, by relaxing the `#[trusted_relayer]` guard to also permit callers who are the recorded `fee_recipient` in the proof.

### Proof of Concept

1. Relayer stakes ≥ 1 000 NEAR and becomes trusted.
2. Relayer calls `ft_on_transfer` with a `FastFinTransferMsg` targeting an EVM address, fronting 1 000 USDC to the user. A `FastTransferStatus` entry is written to `fast_transfers`.
3. The second leg (NEAR → EVM) is initiated; a `TransferMessage` with `origin_transfer_id` pointing to the fast transfer is stored in `pending_transfers`.
4. Relayer calls `resign_trusted_relayer`. Stake is returned; relayer is removed from the trusted set.
5. The EVM destination finalizes the transfer and emits a `FinTransfer` event with `fee_recipient = relayer`.
6. Relayer attempts `claim_fee` with the EVM proof. The `#[trusted_relayer]` macro panics because the relayer is no longer trusted.
7. No other account can call `claim_fee` for this transfer (the `fee_recipient == predecessor_account_id` check blocks it).
8. The fee is permanently locked in the bridge contract. [1](#0-0) [4](#0-3) [2](#0-1)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1054-1063)
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
```

**File:** near/omni-bridge/src/lib.rs (L1066-1133)
```rust
    #[private]
    #[payable]
    pub fn claim_fee_callback(
        &mut self,
        #[serializer(borsh)] predecessor_account_id: &AccountId,
        #[callback_result]
        #[serializer(borsh)]
        call_result: Result<ProverResult, PromiseError>,
    ) -> PromiseOrValue<()> {
        let Ok(ProverResult::FinTransfer(fin_transfer)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };

        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
        require!(
            self.factories
                .get(&fin_transfer.emitter_address.get_chain())
                == Some(fin_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);

        if let Some(origin_transfer_id) = transfer_message.origin_transfer_id.clone() {
            let mut fast_transfer = FastTransfer::from_transfer(
                transfer_message.clone(),
                self.get_token_id(&transfer_message.token),
            );
            fast_transfer.transfer_id = origin_transfer_id;

            if let Some(fast_transfer_status) = self.get_fast_transfer_status(&fast_transfer.id()) {
                // For fast transfers we need to wait for finalization of the first leg (Origin chain -> Near) before allowing fee claim.
                // This confirms that fast transfer was executed with correct parameters.
                // Othewise malicious relayer can create a fast transfer with arbitrary high fee and claim it here.
                if fast_transfer_status.finalised {
                    self.remove_fast_transfer(&fast_transfer.id());
                } else {
                    env::panic_str(BridgeError::FastTransferNotFinalised.to_string().as_str());
                }
            }
        }

        let token = self.get_token_id(&transfer_message.token);
        let token_address = self
            .get_token_address(transfer_message.get_destination_chain(), token.clone())
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

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

**File:** near/omni-tests/src/relayer_staking.rs (L338-368)
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

        Ok(())
```
