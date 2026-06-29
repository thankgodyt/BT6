### Title
Relayer Who Resigns or Is Rejected Cannot Claim Pending Bridge Fees, Permanently Freezing Locked Tokens - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `claim_fee` function in the NEAR omni-bridge contract is gated by the `#[trusted_relayer]` macro. A relayer who has signed transfers (designating themselves as `fee_recipient`) and subsequently resigns via `resign_trusted_relayer` — or is forcibly removed via `reject_relayer_application` — permanently loses the ability to call `claim_fee`. Because `claim_fee_callback` also enforces `fee_recipient == predecessor_account_id`, no other party can claim the fee on their behalf. The fee tokens locked in `pending_transfers` are permanently frozen.

### Finding Description

The bridge's NEAR→Foreign transfer lifecycle requires a trusted relayer to:
1. Call `sign_transfer` (setting `fee_recipient` to themselves)
2. Submit the MPC signature to the destination chain
3. After the destination chain finalizes, call `claim_fee` on NEAR with a proof

`claim_fee` carries two independent access restrictions:

**Restriction 1 — trusted-relayer gate:** [1](#0-0) 

**Restriction 2 — only the fee_recipient can call:** [2](#0-1) 

Together these mean: only the exact account that is both (a) a currently-trusted relayer and (b) the `fee_recipient` embedded in the proof can ever claim the fee.

If the relayer resigns before step 3: [3](#0-2) 

…or is forcibly rejected by the DAO: [4](#0-3) 

…their trusted status is immediately revoked. The `claim_fee` call will revert on the `#[trusted_relayer]` check. No substitute caller can satisfy both restrictions simultaneously. The transfer message — and the fee tokens it encumbers — remains in `pending_transfers` indefinitely with no removal path.

For non-deployed (externally-issued) tokens, the fee amount is tracked in `locked_tokens` and the underlying tokens sit in the bridge contract: [5](#0-4) 

There is no cancel-transfer or admin-sweep function visible in the contract that could recover these funds.

### Impact Explanation

Permanent freezing of bridged funds. The fee portion of every pending NEAR→Foreign transfer signed by the resigned/rejected relayer is irrecoverably locked inside the bridge contract. For non-deployed tokens this means real user funds (the fee slice of each transfer amount) are stuck. The `locked_tokens` accounting is also permanently inflated, which can affect future liquidity calculations.

### Likelihood Explanation

Realistic. A relayer may resign voluntarily at any time after signing transfers but before the destination chain finalizes them (a window that can span minutes to hours depending on chain congestion and proof availability). The DAO can also forcibly reject an active relayer at any time via `reject_relayer_application`, which is an unprivileged-user-triggerable scenario if the DAO acts on a complaint. The attacker-controlled entry path is simply: (1) become a trusted relayer, (2) sign transfers with yourself as `fee_recipient`, (3) resign — all three steps are permissionless for any account that meets the stake requirement.

### Recommendation

Remove the `#[trusted_relayer]` gate from `claim_fee`, or replace it with a check that the caller is the `fee_recipient` recorded in the proof (which `claim_fee_callback` already enforces). Trusted-relayer status is a prerequisite for *signing* transfers but should not be required for *collecting already-earned fees*. Alternatively, allow a designated fallback address or the DAO to sweep unclaimed fees from pending transfers belonging to removed relayers.

### Proof of Concept

1. Relayer `R` calls `apply_for_trusted_relayer` with ≥ 1000 NEAR stake and waits for the activation period.
2. User initiates a NEAR→Ethereum transfer with a non-zero fee.
3. `R` calls `sign_transfer(transfer_id, fee_recipient = R, fee = ...)`. [6](#0-5) 
4. The MPC signature is delivered to Ethereum; the destination contract finalizes the transfer and emits a `FinTransfer` event.
5. Before `R` calls `claim_fee`, `R` calls `resign_trusted_relayer`. `R` is no longer trusted.
6. `R` attempts `claim_fee(args)` — the `#[trusted_relayer]` macro panics. No other account can call it because `fee_recipient == predecessor_account_id` would fail.
7. The transfer message remains in `pending_transfers` forever; the fee tokens are permanently frozen. [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-452)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
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

**File:** near/omni-bridge/src/lib.rs (L1083-1086)
```rust
        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```

**File:** near/omni-bridge/src/lib.rs (L1128-1133)
```rust
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```

**File:** near/omni-tests/src/relayer_staking.rs (L339-344)
```rust
        applicant
            .call(env.bridge_contract.id(), "resign_trusted_relayer")
            .max_gas()
            .transact()
            .await?
            .into_result()?;
```

**File:** near/omni-tests/src/relayer_staking.rs (L469-475)
```rust
        dao_account
            .call(env.bridge_contract.id(), "reject_relayer_application")
            .args_json(json!({"account_id": applicant.id()}))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
```
