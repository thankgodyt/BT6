### Title
Weak Default Finality Levels in `MpcOmniProver::init()` Allow Proof Acceptance on Non-Finalized Blocks — (`File: near/omni-prover/mpc-omni-prover/src/lib.rs`)

---

### Summary

`MpcOmniProver::init()` hardcodes two sub-finalized default finality levels: `EvmFinality::Latest` for the Abstract chain (`ChainKind::Abs`) and `StarknetFinality::AcceptedOnL2` for Starknet (`ChainKind::Strk`). These are the weakest available finality tags for their respective chains and offer no guarantees against sequencer reorgs before L1 settlement. A relayer can submit a valid MPC-attested proof for a transfer that exists only in a non-finalized block; if the source chain reorgs that block, the bridge has already minted tokens on NEAR for a transfer that no longer exists on the source chain.

---

### Finding Description

In `MpcOmniProver::init()`, the contract initializes its per-chain finality map with:

```rust
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
finalities.insert(
    ChainKind::Strk,
    MpcFinality::Starknet(StarknetFinality::AcceptedOnL2),
);
``` [1](#0-0) 

`EvmFinality::Latest` is the head of the chain — the most recent block produced by the Abstract sequencer, with zero reorg protection. Abstract is a ZKsync-based ZK-rollup; its "latest" blocks are not yet proven or settled on Ethereum L1. The sequencer can reorg these blocks before submitting a validity proof to L1.

`StarknetFinality::AcceptedOnL2` means the transaction is accepted by the Starknet sequencer but not yet proven and settled on Ethereum L1 (`AcceptedOnL1`). The Starknet sequencer can reorg `AcceptedOnL2` transactions before L1 proof submission.

The `verify_proof` function is publicly callable with no access control. It enforces that the caller's submitted `sign_payload` matches the configured finality for the chain:

```rust
require!(
    Self::request_matches_finality(&payload_v1.request, finality),
    ProverError::FinalityMismatch.as_ref()
);
``` [2](#0-1) 

`request_matches_finality` enforces equality between the submitted finality and the configured finality: [3](#0-2) 

So a proof submitted with `EvmFinality::Latest` (for Abstract) or `StarknetFinality::AcceptedOnL2` (for Starknet) will pass this check and proceed to MPC verification. The MPC network honestly reads the transaction at the requested finality level and signs a payload attesting to its existence. The bridge then mints tokens on NEAR.

The `set_finality` method is `#[private]` (contract-only), so these defaults cannot be corrected by any external actor without a contract-level governance action: [4](#0-3) 

---

### Impact Explanation

If the Abstract sequencer or Starknet sequencer reorgs a block after the MPC network has attested to a transaction in it, the bridge has already minted bridged tokens on NEAR for a transfer that no longer exists on the source chain. This constitutes unauthorized minting of bridged funds — the attacker holds NEAR-side tokens while the source-chain lock/burn has been rolled back, effectively double-spending.

This matches the allowed impact scope: **unauthorized minting / loss of bridged funds** and **light-client/proof verification bypass enabling invalid finalization**.

---

### Likelihood Explanation

Abstract (ZKsync-based) and Starknet both use centralized sequencers that batch transactions and submit proofs to Ethereum L1 periodically. Before L1 proof submission, the sequencer can reorg its own blocks. While sequencer reorgs are rare in normal operation, they are possible under:
- Sequencer bugs or crashes
- Deliberate sequencer manipulation (sequencer is a single entity)
- Network partitions before L1 batch submission

A sophisticated attacker who can influence or predict sequencer behavior (e.g., by exploiting sequencer MEV or timing windows) can exploit this window. The attack requires no privileged access — any relayer can submit a proof for a "latest" block transaction.

---

### Recommendation

Replace the default finality levels with the strongest available finality for each chain:

- For `ChainKind::Abs` (Abstract / ZKsync): use `EvmFinality::Finalized` (L1-settled) instead of `EvmFinality::Latest`.
- For `ChainKind::Strk` (Starknet): use `StarknetFinality::AcceptedOnL1` instead of `StarknetFinality::AcceptedOnL2`.

This mirrors the fix recommended in the external report: use finalized block tags that represent the settled state of the network, so that in the event of a non-finality incident, the bridge will not process transfers based on data that may change.

---

### Proof of Concept

1. Attacker initiates a bridge transfer on Abstract mainnet (locking tokens in the Abstract bridge contract). The transaction lands in the latest block (not yet L1-proven).
2. Attacker (acting as relayer) calls `mpc-omni-prover.verify_proof()` with a `MpcVerifyProofArgs` containing a `ForeignChainRpcRequest::Abstract(EvmRpcRequest { finality: EvmFinality::Latest, ... })`.
3. `request_matches_finality` passes because the configured finality for `ChainKind::Abs` is `EvmFinality::Latest`.
4. The MPC network reads the transaction at "latest" and returns a signed `VerifyForeignTransactionResponse`.
5. `verify_callback` validates the payload hash and calls `parse_evm_proof`, returning a valid `ProverResult::InitTransfer`.
6. The bridge mints the corresponding tokens on NEAR to the attacker's account.
7. The Abstract sequencer reorgs the block (before L1 proof submission), rolling back the original lock transaction.
8. Attacker holds NEAR-side tokens; the source-chain lock no longer exists. Net result: unauthorized minting of bridged funds. [1](#0-0) [5](#0-4) [6](#0-5)

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

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L73-76)
```rust
    #[private]
    pub fn set_finality(&mut self, chain_kind: ChainKind, finality: MpcFinality) {
        self.finalities.insert(chain_kind, finality);
    }
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L78-115)
```rust
    #[allow(clippy::needless_pass_by_value)]
    pub fn verify_proof(&self, #[serializer(borsh)] input: Vec<u8>) -> Promise {
        let args = MpcVerifyProofArgs::try_from_slice(&input).near_expect(ProverError::ParseArgs);

        let sign_payload = ForeignTxSignPayload::try_from_slice(&args.sign_payload)
            .near_expect(ProverError::ParseArgs);

        let ForeignTxSignPayload::V1(ref payload_v1) = sign_payload;

        let chain_kind = Self::request_to_chain_kind(&payload_v1.request)
            .near_expect(ProverError::UnsupportedChain);

        let finality = self
            .finalities
            .get(&chain_kind)
            .near_expect(ProverError::UnsupportedChain);

        require!(
            Self::request_matches_finality(&payload_v1.request, finality),
            ProverError::FinalityMismatch.as_ref()
        );

        let request_args = VerifyForeignTransactionRequestArgs {
            request: payload_v1.request.clone(),
            domain_id: DomainId(FOREIGN_TX_DOMAIN_ID),
            payload_version: ForeignTxPayloadVersion::V1,
        };

        ext_mpc_contract::ext(self.mpc_contract_id.clone())
            .with_static_gas(VERIFY_FOREIGN_TX_GAS)
            .with_attached_deposit(ONE_YOCTO)
            .verify_foreign_transaction(request_args)
            .then(
                Self::ext(near_sdk::env::current_account_id())
                    .with_static_gas(VERIFY_CALLBACK_GAS)
                    .verify_callback(args.proof_kind, args.sign_payload, chain_kind),
            )
    }
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L117-152)
```rust
    #[allow(clippy::needless_pass_by_value)]
    #[private]
    #[handle_result]
    #[result_serializer(borsh)]
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
