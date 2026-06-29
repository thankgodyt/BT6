### Title
`EvmFinality::Latest` Used for Abstract Chain Proof Verification Enables Double-Spend via Sequencer Reorg - (File: `near/omni-prover/mpc-omni-prover/src/lib.rs`)

---

### Summary

`MpcOmniProver` is hardcoded to accept only `EvmFinality::Latest` proofs for the Abstract chain (`ChainKind::Abs`). Because `EvmFinality::Latest` refers to the most recently sequenced block — which is not yet proven or finalized on L1 — a transaction verified at this level can be reorganized away by the Abstract chain sequencer. The bridge will have already minted tokens on NEAR, while the original lock on Abstract chain is erased, enabling a double-spend.

---

### Finding Description

In `MpcOmniProver::init()`, the finality level for Abstract chain is set to `EvmFinality::Latest`:

```rust
// near/omni-prover/mpc-omni-prover/src/lib.rs:57
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
```

The `request_matches_finality` function enforces this strictly — it rejects any proof that does not carry exactly `EvmFinality::Latest` for Abstract chain:

```rust
// near/omni-prover/mpc-omni-prover/src/lib.rs:163-174
fn request_matches_finality(request: &ForeignChainRpcRequest, finality: &MpcFinality) -> bool {
    match (request, finality) {
        (
            ForeignChainRpcRequest::Ethereum(args) | ForeignChainRpcRequest::Abstract(args),
            MpcFinality::Evm(finality),
        ) => args.finality == *finality,
        ...
    }
}
```

This means:
- Proofs at `EvmFinality::Finalized` or `EvmFinality::Safe` are **rejected** for Abstract chain.
- Only proofs at the non-finalized "latest" block are **accepted**.

The MPC network then verifies the transaction at this latest block and returns a signed response. In `verify_callback`, the hash is checked and the event is parsed, ultimately returning a `ProverResult` that triggers `fin_transfer_callback` in the main bridge contract to mint or release tokens on NEAR.

Abstract chain is built on ZKsync Era (a ZK rollup). At the "latest" finality level, blocks are sequenced but not yet proven on L1. The sequencer retains the ability to reorganize these blocks before they are committed to Ethereum. If such a reorg occurs after the NEAR bridge has finalized the transfer, the attacker's lock on Abstract chain is erased while their NEAR tokens remain.

The `finalised_transfers` set prevents replay of the same `TransferId`, but this is irrelevant: the attacker does not need to replay — they already received tokens on NEAR before the reorg.

---

### Impact Explanation

An attacker who initiates a lock on Abstract chain, submits the proof while the transaction is in the "latest" block, and then causes or benefits from a sequencer reorg, will have:
- Received minted/released tokens on NEAR (irreversible).
- Had their Abstract chain lock transaction erased by the reorg (tokens restored on Abstract chain).

This is an unauthorized minting / double-spend of bridged funds. The severity is critical because the bridge's escrow accounting is permanently broken: NEAR tokens are minted against a lock that no longer exists on Abstract chain.

---

### Likelihood Explanation

Abstract chain (ZKsync Era-based) sequencers can reorganize "latest" blocks before L1 finalization. While routine reorgs are uncommon, they are a known property of ZK rollup "latest" state. A sequencer bug, network partition, or deliberate sequencer action can trigger this. The bridge's design actively forces all Abstract chain proofs through this non-finalized path, making every Abstract chain inbound transfer subject to this risk window.

---

### Recommendation

Change the configured finality for Abstract chain from `EvmFinality::Latest` to `EvmFinality::Finalized` (or `EvmFinality::Safe`), consistent with how other EVM chains should be handled. This ensures the MPC network only attests to transactions that are proven and committed on L1, eliminating the reorg window.

```rust
// near/omni-prover/mpc-omni-prover/src/lib.rs
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Finalized));
```

---

### Proof of Concept

1. Attacker calls the Abstract chain bridge contract to lock 1000 USDC. Transaction `T` lands in the latest (unfinalized) block `B`.
2. Attacker (or a cooperating relayer) immediately calls `fin_transfer()` on the NEAR bridge, supplying a `MpcVerifyProofArgs` with `EvmFinality::Latest` for `ChainKind::Abs`.
3. `verify_proof()` passes `request_matches_finality` (line 95–98) because the configured finality is `EvmFinality::Latest`.
4. The MPC network verifies `T` at block `B` and returns a valid `VerifyForeignTransactionResponse`.
5. `verify_callback` (line 121) confirms `expected_hash == mpc_response.payload_hash` and returns `ProverResult::InitTransfer`.
6. `fin_transfer_callback` (line 700) mints 1000 USDC-equivalent tokens to the attacker on NEAR. `finalised_transfers` records the `TransferId`.
7. The Abstract chain sequencer reorgs block `B`, removing transaction `T`. The attacker's 1000 USDC on Abstract chain is restored.
8. Attacker holds 1000 USDC on Abstract chain **and** 1000 USDC-equivalent on NEAR. Bridge escrow is insolvent.

---

**Key citations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L55-67)
```rust
    pub fn init(mpc_contract_id: AccountId) -> Self {
        let mut finalities = HashMap::new();
        finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
        finalities.insert(
            ChainKind::Strk,
            MpcFinality::Starknet(StarknetFinality::AcceptedOnL2),
        );

        Self {
            mpc_contract_id,
            finalities,
        }
    }
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L95-98)
```rust
        require!(
            Self::request_matches_finality(&payload_v1.request, finality),
            ProverError::FinalityMismatch.as_ref()
        );
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L121-151)
```rust
    pub fn verify_callback(
        &self,
        #[serializer(borsh)] proof_kind: ProofKind,
        #[serializer(borsh)] sign_payload_bytes: Vec<u8>,
        #[serializer(borsh)] chain_kind: ChainKind,
        #[callback_result] call_result: Result<
            VerifyForeignTransactionResponse,
            near_sdk::PromiseError,
        >,
    ) -> Result<ProverResult, String> {
        let mpc_response = call_result.map_err(|_| ProverError::InvalidProof.to_string())?;

        let sign_payload = ForeignTxSignPayload::try_from_slice(&sign_payload_bytes)
            .map_err(|_| ProverError::ParseArgs.to_string())?;

        let expected_hash = sign_payload
            .compute_msg_hash()
            .map_err(|_| ProverError::InvalidPayloadHash.to_string())?;

        if expected_hash != mpc_response.payload_hash {
            return Err(ProverError::InvalidPayloadHash.to_string());
        }

        let ForeignTxSignPayload::V1(ref payload_v1) = sign_payload;

        if chain_kind == ChainKind::Strk {
            Self::parse_starknet_result(proof_kind, chain_kind, payload_v1)
        } else {
            let log_entry_data = Self::extract_evm_log(payload_v1)?;
            parse_evm_proof(proof_kind, chain_kind, log_entry_data)
        }
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L163-174)
```rust
    fn request_matches_finality(request: &ForeignChainRpcRequest, finality: &MpcFinality) -> bool {
        match (request, finality) {
            (
                ForeignChainRpcRequest::Ethereum(args) | ForeignChainRpcRequest::Abstract(args),
                MpcFinality::Evm(finality),
            ) => args.finality == *finality,
            (ForeignChainRpcRequest::Starknet(args), MpcFinality::Starknet(finality)) => {
                args.finality == *finality
            }
            _ => false,
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L700-745)
```rust
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
```

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```
