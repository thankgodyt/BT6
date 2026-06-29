### Title
Permissionless Trusted-Relayer Auto-Promotion Enables Fee Theft via `sign_transfer` `fee_recipient` Manipulation — (File: `near/omni-bridge/src/lib.rs`)

### Summary

The `apply_for_trusted_relayer` mechanism auto-promotes any applicant to trusted-relayer status after a configurable waiting period elapses, with no DAO approval required. Once promoted, a trusted relayer can call `sign_transfer` on **any** pending transfer and set an arbitrary `fee_recipient`, redirecting all accumulated transfer fees to themselves. The stake is fully recoverable via `resign_trusted_relayer`, making the net cost of the attack zero beyond the opportunity cost of the waiting period.

### Finding Description

The bridge implements a permissionless relayer-staking system. Any account can call `apply_for_trusted_relayer` with a deposit meeting `stake_required` (default 1 000 NEAR). After `waiting_period_ns` elapses (default 7 days, 604 800 000 000 000 ns), `is_trusted_relayer` returns `true` automatically — no DAO vote, no human approval. [1](#0-0) 

Once trusted, the attacker calls `sign_transfer` on every pending transfer in the bridge. The function accepts a caller-supplied `fee_recipient: Option<AccountId>` and passes it verbatim into the `TransferMessagePayload` that the MPC network signs: [2](#0-1) 

There is no check that the caller is the relayer who originally serviced the transfer, nor any check that `fee_recipient` matches a pre-agreed address. The MPC signs whatever `fee_recipient` the trusted relayer supplies. On the destination chain the fee is paid to that address.

After draining fees, the attacker calls `resign_trusted_relayer`, which returns the full stake: [3](#0-2) 

The same `#[trusted_relayer]` guard protects `fin_transfer` and `submit_transfer_to_utxo_chain_connector`, so the same auto-promotion path grants access to those entry points as well. [4](#0-3) 

### Impact Explanation

A malicious actor who completes the waiting period can redirect the `fee_recipient` field in every pending `sign_transfer` call, stealing all bridge fees that legitimate relayers are owed. Because the stake is returned on resignation, the attack is economically free if the stolen fees exceed gas costs. This is fee mis-accounting that directly changes relayer and protocol balances. The principal transfer amounts reach the correct recipients (the prover still validates proofs), but the entire fee layer is compromised.

### Likelihood Explanation

The entry path is fully permissionless — any account with 1 000 NEAR can execute it. The 7-day waiting period is the only friction. If aggregate pending-transfer fees exceed the opportunity cost of locking 1 000 NEAR for 7 days, the attack is profitable. During periods of high bridge activity this threshold is easily crossed. No privileged access, leaked keys, or external dependency failure is required.

### Recommendation

1. **Require explicit DAO approval** before an applicant becomes a trusted relayer, removing the auto-promotion path entirely.
2. **Bind `fee_recipient` at transfer initiation** (store it in `TransferMessage`) so `sign_transfer` cannot override it with a caller-supplied value.
3. **Add a withdrawal delay** after `resign_trusted_relayer` so the stake remains at risk for a challenge period, analogous to optimistic-rollup exit windows.
4. **Enforce a minimum stake-to-fee ratio** so the economic cost of the attack always exceeds the maximum extractable fee value.

### Proof of Concept

```
1. Attacker calls apply_for_trusted_relayer with 1 000 NEAR deposit.
   → RelayerApplication recorded; waiting_period_ns = 604_800_000_000_000 ns (7 days).

2. After 7 days, is_trusted_relayer(attacker) returns true automatically.
   → No DAO action taken.

3. Attacker enumerates all pending transfers (via on-chain events / indexer).

4. For each transfer_id with a non-zero fee, attacker calls:
     sign_transfer(
       transfer_id = <victim_transfer_id>,
       fee_recipient = Some(attacker_account),
       fee = <fee stored in transfer message>
     )
   → MPC signs TransferMessagePayload with fee_recipient = attacker.
   → On the destination chain the fee is paid to the attacker, not the legitimate relayer.

5. Attacker calls resign_trusted_relayer.
   → Full 1 000 NEAR stake returned.
   → Net cost: zero (minus gas). Net gain: all stolen fees.
``` [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-tests/src/relayer_staking.rs (L100-160)
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

        // Verify stake is stored
        let stake: Option<U128> = env
            .bridge_contract
            .view("get_relayer_stake")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(stake.is_some());
        assert!(stake.unwrap().0 >= 1_000 * 10u128.pow(24));

        // Verify application is no longer pending
        let application: Option<serde_json::Value> = env
            .bridge_contract
            .view("get_relayer_application")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(application.is_none());

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

**File:** near/omni-tests/src/relayer_staking.rs (L495-509)
```rust
    async fn test_set_relayer_config(
        #[from(locker_wasm)] locker: Vec<u8>,
        #[from(mock_prover_wasm)] prover: Vec<u8>,
    ) -> anyhow::Result<()> {
        let env = TestEnv::new(locker, prover).await?;

        // Verify defaults
        let config: serde_json::Value = env
            .bridge_contract
            .view("get_relayer_config")
            .await?
            .json()?;
        let default_stake = (1_000u128 * 10u128.pow(24)).to_string();
        assert_eq!(config["stake_required"], json!(default_stake));
        assert_eq!(config["waiting_period_ns"], json!(U64(604_800_000_000_000)));
```

**File:** near/omni-bridge/src/lib.rs (L444-521)
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
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );

        let message = DestinationChainMsg::from_json(&transfer_message.msg)
            .and_then(|s| s.destination_msg())
            .unwrap_or_default();

        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };

        let payload = near_sdk::env::keccak256_array(
            transfer_payload
                .encode_hashable()
                .near_expect(BridgeError::Borsh),
        );

        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_TRANSFER_CALLBACK_GAS)
                    .sign_transfer_callback(transfer_payload, &transfer_message.fee),
            )
    }
```

**File:** near/omni-bridge/src/lib.rs (L748-756)
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
```
