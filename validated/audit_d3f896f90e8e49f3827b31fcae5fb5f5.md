Audit Report

## Title
Silent `fee_recipient.parse().ok()` Causes Permanent `pending_transfer` Freeze via `claim_fee_callback` Panic — (`near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs`, `near/omni-bridge/src/lib.rs`)

## Summary

In `TryInto<FinTransferMessage> for ParsedVAA`, any unparseable `fee_recipient` string (empty, invalid characters, >64 bytes) is silently converted to `None` via `.parse().ok()`. The downstream `claim_fee_callback` unconditionally panics on `None` **before** calling `remove_transfer_message`, leaving the `pending_transfer` entry permanently committed in state with no recovery path. The same silent-`None` pattern exists in the EVM `FinTransferMessage` parser.

## Finding Description

**Root cause — silent `None` in the Wormhole parser:**

`TryInto<FinTransferMessage> for ParsedVAA` at line 197 uses `.parse().ok()` on the raw Borsh-decoded `fee_recipient` string. Any value that fails `AccountId::from_str` — including an empty string — silently becomes `None`. No error is returned; `verify_vaa_callback` returns `Ok(ProverResult::FinTransfer(...))` with `fee_recipient: None`. [1](#0-0) 

The identical pattern exists in the EVM parser: [2](#0-1) 

By contrast, `InitTransferMessage` parsing uses `.parse().map_err(stringify)?`, which propagates the error and aborts the conversion — the correct pattern that `FinTransferMessage` does not follow: [3](#0-2) 

**Panic before state cleanup in `claim_fee_callback`:**

`claim_fee_callback` calls `env::panic_str` at line 1080 when `fee_recipient` is `None`. The `remove_transfer_message` call that removes the entry from `pending_transfers` is at line 1094 — unreachable after the panic. [4](#0-3) 

Under NEAR's receipt model, a panic in a callback only reverts state changes made within that callback's own execution. The `pending_transfer` entry was committed in a prior receipt (during `init_transfer` / `fin_transfer`) and is not touched by this panic. It remains in `pending_transfers` indefinitely. [5](#0-4) 

**No recovery path:**

`remove_transfer_message` is the only function that removes entries from `pending_transfers` in the fee-claim flow. There is no DAO-gated or admin `force_remove_pending_transfer` function. The same VAA can be re-submitted (if the Wormhole proxy does not track used VAAs), but it will always produce `fee_recipient: None` and always panic. [6](#0-5) 

## Impact Explanation

When `pending_transfer` cannot be removed:

1. **Storage deposit permanently frozen**: `remove_transfer_message` credits the storage refund back to `accounts_balances` for the transfer initiator. Since it is never reached, those NEAR tokens are permanently locked in the bridge contract.
2. **`locked_tokens` counter permanently inflated**: `send_fee_internal` (which decrements `locked_tokens` for the `(chain, token)` pair) is never reached, corrupting the bridge's accounting for that token.
3. **Relayer fee permanently lost**: The relayer cannot claim their fee for the finalized transfer.

This constitutes permanent freezing of bridged funds and balance/escrow mis-accounting, matching the Critical allowed impact scope.

## Likelihood Explanation

The precondition is a Wormhole-signed VAA reaching `claim_fee` with an invalid `fee_recipient` string. The `#[trusted_relayer]` gate on `claim_fee` requires the caller to be a staked relayer, but the staking system is fully permissionless: anyone can call `apply_for_trusted_relayer` with 1,000 NEAR and be auto-promoted after the waiting period (default 7 days), as confirmed by the test suite. [7](#0-6) 

The `feeRecipient` field in the source-chain `FinTransfer` event is a raw Solidity `string` with no NEAR account ID format validation at the EVM layer. A malicious or buggy relayer that controls the finalization call on the source chain can supply an empty or malformed string. Wormhole guardians attest to what was emitted on-chain; they do not validate NEAR account ID semantics. Once such a VAA is produced, the freeze is permanent and repeatable.

## Recommendation

1. **Hard-error on invalid `fee_recipient`** in both parsers, matching the pattern used for `recipient` in `InitTransferMessage`:
   ```rust
   fee_recipient: if transfer.fee_recipient.is_empty() {
       None
   } else {
       Some(transfer.fee_recipient.parse().map_err(stringify)?)
   },
   ```
2. **Return `Err` instead of panicking** in `claim_fee_callback` when `fee_recipient` is `None`, so the callback fails gracefully without leaving `pending_transfer` stranded.
3. **Add a DAO-gated `force_remove_pending_transfer`** escape hatch to recover any future stuck entries.

## Proof of Concept

**Unit test** (`parsed_vaa.rs`): Construct a `FinTransferWh` with `fee_recipient = ""`, Borsh-encode it as a fake VAA payload, call `TryInto<FinTransferMessage>`, assert `fee_recipient == None` — demonstrating the silent conversion succeeds without error.

**Integration test** (`claim_fee_callback`): Insert a `pending_transfer` into state directly. Call `claim_fee_callback` with `ProverResult::FinTransfer(FinTransferMessage { fee_recipient: None, .. })`. Assert the call panics with `FeeRecipientNotSetOrEmpty`. Then assert `get_transfer_message(transfer_id)` still returns the entry — proving it was not removed by the panicking callback. [8](#0-7) [9](#0-8)

### Citations

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L134-141)
```rust
#[derive(Debug, BorshDeserialize)]
struct FinTransferWh {
    payload_type: ProofKind,
    transfer_id: TransferId,
    token_address: OmniAddress,
    amount: u128,
    fee_recipient: String,
}
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L173-173)
```rust
            recipient: transfer.recipient.parse().map_err(stringify)?,
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L195-204)
```rust
        Ok(FinTransferMessage {
            transfer_id: transfer.transfer_id,
            fee_recipient: transfer.fee_recipient.parse().ok(),
            amount: transfer.amount.into(),
            emitter_address: OmniAddress::new_from_slice(
                transfer.token_address.get_chain(),
                &self.emitter_address,
            )?,
        })
    }
```

**File:** near/omni-types/src/evm/events.rs (L106-106)
```rust
            fee_recipient: event.data.feeRecipient.parse().ok(),
```

**File:** near/omni-bridge/src/lib.rs (L222-222)
```rust
    pub pending_transfers: LookupMap<TransferId, TransferMessageStorage>,
```

**File:** near/omni-bridge/src/lib.rs (L1066-1094)
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

**File:** near/omni-tests/src/relayer_staking.rs (L81-139)
```rust
    async fn test_apply_auto_promote_relayer(
        #[from(locker_wasm)] locker: Vec<u8>,
        #[from(mock_prover_wasm)] prover: Vec<u8>,
    ) -> anyhow::Result<()> {
        let env = TestEnv::new(locker, prover).await?;

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
