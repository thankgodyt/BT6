### Title
Permissionlessly Registered Trusted Relayer Can Redirect Fast-Transfer Recipient to Steal User Funds - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The NEAR Omni Bridge allows any account to self-register as a trusted relayer by depositing stake and waiting a configurable period, after which they are automatically promoted. Once trusted, a relayer calls `fast_fin_transfer` (via `ft_on_transfer`) and supplies a `FastFinTransferMsg` that includes the `recipient` field. The bridge does not validate that the relayer-supplied `recipient` matches the intended recipient recorded in the originating cross-chain transfer. A malicious relayer can therefore redirect the fast-finalization payment to an address they control, mark the transfer as finalized, and collect the full reimbursement when the real proof arrives — stealing the user's bridged funds at zero net cost.

### Finding Description

**Root cause — permissionless relayer registration:**

Any account can call `apply_for_trusted_relayer` with sufficient stake. After the `waiting_period_ns` elapses, `is_trusted_relayer` returns `true` automatically (auto-promote path), with no mandatory DAO approval required. [1](#0-0) 

**Root cause — unvalidated recipient in `fast_fin_transfer`:**

Inside `fast_fin_transfer` (called when the relayer sends tokens via `ft_on_transfer`), the only checks performed are:

1. `is_trusted_relayer(&signer_id)` — passes for any auto-promoted relayer.
2. Token existence and decimal lookup.
3. Amount arithmetic: `denormalized_amount == amount.0 + denormalized_fee.fee.0`.
4. `!is_unified_transfer_finalised(&transfer_id)` — transfer not yet finalized. [2](#0-1) 

The `FastTransfer` struct is then constructed directly from the relayer-supplied `fast_fin_transfer_msg.recipient` with **no check that this recipient matches the recipient embedded in the originating cross-chain transfer**: [3](#0-2) 

Because the foreign-chain transfer (e.g., EVM `initTransfer`) has not yet been proven on NEAR at the time `fast_fin_transfer` is called, the bridge holds no stored copy of the original recipient to validate against. The relayer is the sole source of truth for `recipient`, `amount`, and `fee`.

**Exploit path:**

1. Attacker deposits sufficient NEAR stake via `apply_for_trusted_relayer` and waits for the auto-promote window.
2. A victim initiates a transfer on EVM: locks 100 USDC, specifies Alice as the NEAR recipient.
3. Attacker (now a trusted relayer) calls `fast_fin_transfer` with `transfer_id` = victim's transfer, `recipient` = attacker's own NEAR address, `amount` = 99 USDC, `fee` = 1 USDC.
4. Bridge sends 99 USDC (attacker's own tokens) to the attacker's address and marks the transfer as finalized.
5. When the real Wormhole VAA / light-client proof arrives, the bridge sees the transfer is already finalized and reimburses the attacker 99 USDC from newly minted / unlocked tokens.
6. Net result: attacker recovers their 99 USDC outlay and retains the 99 USDC sent to themselves. Alice receives nothing.

### Impact Explanation

**Critical.** A permissionlessly registered trusted relayer can redirect any pending fast transfer to an address they control and collect a full reimbursement when the proof is later submitted. This constitutes direct theft of bridged user funds with no residual loss to the attacker (stake is returned on resignation). Every in-flight foreign→NEAR transfer that has not yet been proven is at risk.

### Likelihood Explanation

**High.** Relayer registration is permissionless; the only barrier is the stake deposit and waiting period, both of which are configurable and can be set to low values. The attack requires no privileged keys, no cryptographic break, and no admin collusion. Any actor who can observe the mempool or bridge indexer for pending transfers can execute this immediately after becoming trusted.

### Recommendation

Before executing a fast finalization, the bridge must verify that the relayer-supplied `recipient` (and ideally `amount`/`fee`) matches the values committed in the originating cross-chain event. Two concrete approaches:

1. **Require prior proof registration:** Introduce a separate `register_transfer` step that stores the proof-verified transfer details (recipient, amount, fee) on-chain before any fast finalization is permitted. `fast_fin_transfer` then validates against the stored record.
2. **Include recipient in the transfer ID:** Derive `transfer_id` as a hash that commits to the recipient address, amount, and fee. The relayer must supply matching values or the ID lookup fails.

This mirrors the MetaSwap fix: isolate the entity that holds user value (the bridge) from the entity that executes on behalf of users (the relayer), ensuring newly added relayers cannot redirect funds.

### Proof of Concept

```
1. Attacker calls apply_for_trusted_relayer with stake = stake_required
2. Wait waiting_period_ns blocks → is_trusted_relayer(attacker) == true
3. Victim calls EVM initTransfer(usdc, 100e6, fee=1e6, recipient="alice.near")
   → EVM emits transfer event; transfer_id = (Eth, nonce=42)
4. Attacker calls ft_transfer_call on USDC token contract:
     receiver_id = omni-bridge.near
     amount      = 99_000_000          // attacker's own USDC
     msg         = FastFinTransferMsg {
                     transfer_id: { origin_chain: Eth, origin_nonce: 42 },
                     recipient:   OmniAddress::Near("attacker.near"),  // ← hijacked
                     amount:      U128(99_000_000),
                     fee:         Fee { fee: U128(1_000_000), ... },
                     relayer:     "attacker.near",
                     ...
                   }
5. Bridge: is_trusted_relayer("attacker") → true
           99_000_000 + 1_000_000 == 100_000_000 → true
           !is_unified_transfer_finalised({Eth,42}) → true
   → sends 99 USDC to "attacker.near"; marks transfer finalized
6. Relayer submits Wormhole VAA for transfer_id {Eth,42}
   → bridge sees transfer already finalized → reimburses attacker 99 USDC
7. alice.near receives 0 USDC. Attacker net gain: +99 USDC.
``` [4](#0-3) [5](#0-4)

### Citations

**File:** near/omni-tests/src/relayer_staking.rs (L100-139)
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

        // Verify application exists
        let application: Option<serde_json::Value> = env
            .bridge_contract
            .view("get_relayer_application")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(application.is_some());

        // Before waiting period, relayer should not be trusted
        let is_trusted: bool = env
            .bridge_contract
            .view("is_trusted_relayer")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(!is_trusted);

        // Fast forward past waiting period
        env.worker.fast_forward(100).await?;

        // After waiting period, relayer should be trusted
        let is_trusted: bool = env
            .bridge_contract
            .view("is_trusted_relayer")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(is_trusted);
```

**File:** near/omni-bridge/src/lib.rs (L748-789)
```rust
    #[allow(clippy::needless_pass_by_value)]
    fn fast_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        signer_id: AccountId,
        fast_fin_transfer_msg: FastFinTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(self.is_trusted_relayer(&signer_id), "Relayer is not active");

        let origin_token = self
            .get_token_address(
                fast_fin_transfer_msg.transfer_id.origin_chain,
                token_id.clone(),
            )
            .near_expect(BridgeError::TokenNotFound);

        let decimals = self
            .token_decimals
            .get(&origin_token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let denormalized_amount =
            Self::denormalize_amount(fast_fin_transfer_msg.amount.0, decimals);
        let denormalized_fee = Self::denormalize_fee(&fast_fin_transfer_msg.fee, decimals);
        require!(
            denormalized_amount == amount.0 + denormalized_fee.fee.0,
            BridgeError::InvalidFastTransferAmount.as_ref()
        );

        if self.is_unified_transfer_finalised(&fast_fin_transfer_msg.transfer_id) {
            env::panic_str(BridgeError::TransferAlreadyFinalised.to_string().as_str());
        }

        let fast_transfer = FastTransfer {
            token_id: token_id.clone(),
            recipient: fast_fin_transfer_msg.recipient.clone(),
            amount: U128(denormalized_amount),
            fee: denormalized_fee,
            transfer_id: fast_fin_transfer_msg.transfer_id,
            msg: fast_fin_transfer_msg.msg,
        };
```
