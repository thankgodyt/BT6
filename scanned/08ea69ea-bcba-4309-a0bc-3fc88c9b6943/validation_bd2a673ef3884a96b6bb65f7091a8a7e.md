### Title
Insufficient Finality Levels for Starknet and Abstract Chain Proofs Enable Sequencer-Reorg Double-Spend - (File: near/omni-prover/mpc-omni-prover/src/lib.rs)

### Summary
`MpcOmniProver::init()` hardcodes `StarknetFinality::AcceptedOnL2` for `ChainKind::Strk` and `EvmFinality::Latest` for `ChainKind::Abs`. Both are pre-finality states that the respective chain's sequencer can reverse before L1 settlement. The bridge accepts MPC-verified proofs at these weak finality levels and mints tokens on NEAR, but the source-chain transaction can subsequently be reorged away, enabling double-spending of bridged funds.

### Finding Description
In `MpcOmniProver::init()`, two finality levels are hardcoded:

```rust
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
finalities.insert(
    ChainKind::Strk,
    MpcFinality::Starknet(StarknetFinality::AcceptedOnL2),
);
```

`verify_proof()` enforces that the caller's submitted `sign_payload` must carry a finality tag that exactly matches the configured value via `request_matches_finality()`. Because the configured values are `Latest` and `AcceptedOnL2`, only proofs at those weak levels are accepted — proofs at stronger levels (`Finalized`, `AcceptedOnL1`) are rejected with `FinalityMismatch`.

**Starknet (`AcceptedOnL2`):** On Starknet, `AcceptedOnL2` means the transaction has been sequenced into an L2 block but the corresponding STARK proof has not yet been verified on Ethereum L1. The Starknet sequencer (currently centralized, operated by StarkWare) can reorg L2 blocks at will before L1 settlement. `AcceptedOnL1` is the safe finality level — it means the proof has been verified on Ethereum and the state is cryptographically final.

**Abstract (`EvmFinality::Latest`):** Abstract (chainId 2741) is a ZKsync-based ZK-rollup. `Latest` refers to the most recent L2 block, which has not yet had its ZK proof submitted and verified on Ethereum L1. The Abstract sequencer controls L2 block production and can reorg unproven L2 blocks. `Finalized` would correspond to L1-settled state.

The `verify_proof` → MPC cross-contract call → `verify_callback` flow finalizes the bridge transfer on NEAR (minting tokens) based solely on the MPC network's confirmation that the transaction existed at the configured (weak) finality level. There is no subsequent re-check once the source-chain block is reorged. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
A malicious or compromised Starknet/Abstract sequencer can execute a double-spend:

1. User (or sequencer itself) calls `initTransfer` on the Starknet/Abstract bridge, locking tokens.
2. The sequencer includes the transaction in an L2 block → state becomes `AcceptedOnL2` / `Latest`.
3. A relayer calls `verify_proof` on `MpcOmniProver`; `request_matches_finality` passes because the proof's finality tag matches the configured weak level.
4. The MPC network verifies the transaction and returns a signed `payload_hash`.
5. `verify_callback` confirms `SHA-256(borsh(sign_payload)) == response.payload_hash` and returns a `ProverResult`.
6. `fin_transfer` is called on the NEAR `omni-bridge`, minting bridged tokens to the recipient.
7. The sequencer reorgs the L2 block containing the `initTransfer`, reversing the lock on the source chain and returning the tokens to the sender.
8. The sender now holds tokens on both the source chain and NEAR — a complete double-spend of bridged funds.

This is a **critical** balance manipulation / unauthorized minting impact: bridged token supply on NEAR is inflated without a corresponding locked amount on the source chain. [4](#0-3) 

### Likelihood Explanation
Both Starknet and Abstract use centralized sequencers. The Starknet sequencer is operated by StarkWare; the Abstract sequencer is operated by the Abstract team. A compromised or malicious sequencer can reorg L2 blocks before L1 proof submission at any time. This is not a theoretical edge case — it is an inherent property of pre-finality L2 state. The attack requires no special bridge permissions, no NEAR validator collusion, and no MPC threshold compromise; it only requires the source-chain sequencer to act on its existing authority over unproven L2 blocks.

The external report's analog (Polygon validators exploiting `REQUEST_CONFIRMATIONS = 3`) is structurally identical: a chain operator exploits insufficient confirmation depth to reverse a transaction after the dependent protocol has already acted on it.

### Recommendation
Change the hardcoded finality levels in `MpcOmniProver::init()` to require true L1-settled finality:

- **Starknet:** `StarknetFinality::AcceptedOnL1` — the STARK proof has been verified on Ethereum L1 and the state is cryptographically irreversible.
- **Abstract:** `EvmFinality::Finalized` — the ZK proof has been submitted and verified on Ethereum L1.

```rust
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Finalized));
finalities.insert(
    ChainKind::Strk,
    MpcFinality::Starknet(StarknetFinality::AcceptedOnL1),
);
``` [1](#0-0) [5](#0-4) 

### Proof of Concept

**Starknet double-spend path:**

1. Attacker (or colluding sequencer) calls `initTransfer` on the Starknet bridge, locking 1000 STRK.
2. Starknet sequencer includes the transaction → state is `AcceptedOnL2`.
3. Relayer submits `MpcVerifyProofArgs` with `StarknetRpcRequest { finality: StarknetFinality::AcceptedOnL2, ... }` to `verify_proof`.
4. `request_matches_finality` at line 169–171 evaluates `args.finality == *finality` → `AcceptedOnL2 == AcceptedOnL2` → `true`. No panic.
5. MPC cross-contract call to `verify_foreign_transaction` succeeds; `verify_callback` confirms payload hash and returns `ProverResult::InitTransfer`.
6. NEAR `omni-bridge` mints 1000 omni-STRK to the recipient.
7. Starknet sequencer reorgs the block containing the `initTransfer` before submitting the L1 proof. The 1000 STRK are returned to the attacker on Starknet.
8. Attacker holds 1000 STRK on Starknet **and** 1000 omni-STRK on NEAR.

The test `test_request_matches_finality_starknet_mismatch` in the test suite confirms the protocol's own understanding that `AcceptedOnL2` and `AcceptedOnL1` are distinct levels — yet `init()` configures the weaker one as the enforced standard. [6](#0-5) [7](#0-6)

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

**File:** near/omni-types/src/mpc_types.rs (L9-12)
```rust
pub enum MpcFinality {
    Evm(EvmFinality),
    Starknet(StarknetFinality),
}
```

**File:** near/omni-prover/mpc-omni-prover/src/tests.rs (L321-328)
```rust
#[test]
fn test_request_matches_finality_starknet_mismatch() {
    let request = ForeignChainRpcRequest::Starknet(test_starknet_request());
    assert!(!MpcOmniProver::request_matches_finality(
        &request,
        &MpcFinality::Starknet(StarknetFinality::AcceptedOnL2)
    ));
}
```
