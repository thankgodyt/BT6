The code confirms all factual claims in the report. Let me verify the key elements:

Audit Report

## Title
Hardcoded Pre-Finality Levels for Abstract Chain and Starknet Enable Reorg-Based Double-Spend — (`near/omni-prover/mpc-omni-prover/src/lib.rs`)

## Summary
`MpcOmniProver::init()` permanently sets `ChainKind::Abs` to `EvmFinality::Latest` and `ChainKind::Strk` to `StarknetFinality::AcceptedOnL2`. Both are sequencer-accepted but not L1-settled states, meaning the underlying blocks can be reorged before Ethereum L1 finalization. Because `verify_proof()` enforces strict equality between the caller-supplied finality and the stored value, all Abstract and Starknet proofs are structurally required to use these weak finality levels, enabling a deposit-then-reorg double-spend against the NEAR bridge.

## Finding Description
In `init()`, two finality values are hardcoded into the contract state:

```rust
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
finalities.insert(ChainKind::Strk, MpcFinality::Starknet(StarknetFinality::AcceptedOnL2));
``` [1](#0-0) 

`verify_proof()` retrieves the stored finality and enforces strict equality via `request_matches_finality`:

```rust
require!(
    Self::request_matches_finality(&payload_v1.request, finality),
    ProverError::FinalityMismatch.as_ref()
);
``` [2](#0-1) 

`request_matches_finality` performs `args.finality == *finality`, so a proof with `EvmFinality::Finalized` for Abstract chain is rejected; only `EvmFinality::Latest` passes: [3](#0-2) 

The only mutation path, `set_finality`, is `#[private]` — NEAR SDK enforces `predecessor_account_id == current_account_id`. No method in the contract issues a self-call to `set_finality`, so the stored finality values are immutable without a full contract upgrade: [4](#0-3) 

Abstract chain (`ChainKind::Abs`) is a ZKsync-based EVM L2. On ZKsync-based chains, `Latest` refers to the most recently produced sequencer block, which has not yet been proven or settled on Ethereum L1. The sequencer can reorg its own blocks during this window. The test suite confirms the contrast: Ethereum mainnet proofs use `EvmFinality::Finalized`, while Abstract testnet proofs use `EvmFinality::Latest`: [5](#0-4) 

Starknet's `AcceptedOnL2` means the transaction is accepted by the Starknet sequencer but not yet proven on L1. The test fixture for the generic Starknet request uses the stronger `AcceptedOnL1`, while the Starknet Sepolia fixture uses `AcceptedOnL2` — matching the stored value: [6](#0-5) 

## Impact Explanation
This is a **Critical** double-spend / theft of bridged funds. An attacker deposits tokens on Abstract chain or Starknet, obtains an MPC-signed proof while the deposit transaction is in a `Latest`/`AcceptedOnL2` block, submits the proof to the NEAR bridge locker to mint bridged tokens, and then benefits from a sequencer reorg that erases the original deposit from the canonical chain. The attacker retains both the original tokens on the source chain and the minted tokens on NEAR. The NEAR bridge has no mechanism to reverse a completed mint after a source-chain reorg. This matches the allowed impact: *stealing, loss, double-spending, or unauthorized minting of bridged funds*.

## Likelihood Explanation
Abstract chain is a ZKsync-based L2 where the window between a `Latest` block and L1 proof submission can span minutes to hours. Starknet sequencer reorgs before L1 proof are similarly documented. The attack requires no privileged access to the bridge contract — any user can call `verify_proof()` with a `Latest`-finality proof. A sophisticated attacker can monitor the sequencer's L1 submission pipeline and time the proof submission to exploit the pre-settlement window. The finality mismatch check provides no protection because it enforces the weak level, not a strong one.

## Recommendation
1. Change `ChainKind::Abs` finality from `EvmFinality::Latest` to `EvmFinality::Finalized` (or at minimum `EvmFinality::Safe`) in `init()`, matching the treatment of Ethereum mainnet.
2. Change `ChainKind::Strk` finality from `StarknetFinality::AcceptedOnL2` to `StarknetFinality::AcceptedOnL1`, requiring L1 settlement before a Starknet proof is accepted.
3. Make `set_finality` callable by a privileged admin role (e.g., DAO or owner account) rather than only by the contract itself, so finality levels can be adjusted without a full contract upgrade.

## Proof of Concept
**Abstract chain double-spend (unit-test level):**

1. Deploy `MpcOmniProver` via `init()` — `finalities[Abs] = EvmFinality::Latest` is set.
2. Construct `MpcVerifyProofArgs` with `ForeignChainRpcRequest::Abstract(EvmRpcRequest { finality: EvmFinality::Latest, tx_id: <deposit_tx>, ... })`.
3. Call `verify_proof(borsh(args))` — `request_matches_finality` returns `true` (Latest == Latest), the MPC contract is called with the `Latest`-finality request, and the MPC network reads and signs the event from the unfinalized block.
4. `verify_callback` succeeds and returns `ProverResult::InitTransfer`; the NEAR bridge locker mints bridged tokens.
5. The Abstract chain sequencer reorgs the block containing the deposit before L1 proof submission — the deposit is erased from the canonical chain.
6. The attacker holds both the original tokens on Abstract chain and the minted tokens on NEAR; the bridge escrow is undercollateralized.

The existing test `test_request_matches_finality_abstract_mismatch` confirms that `EvmFinality::Finalized` is rejected for Abstract chain requests, proving no stronger finality can be substituted by callers: [7](#0-6)

### Citations

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L56-61)
```rust
        let mut finalities = HashMap::new();
        finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
        finalities.insert(
            ChainKind::Strk,
            MpcFinality::Starknet(StarknetFinality::AcceptedOnL2),
        );
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L73-76)
```rust
    #[private]
    pub fn set_finality(&mut self, chain_kind: ChainKind, finality: MpcFinality) {
        self.finalities.insert(chain_kind, finality);
    }
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L95-98)
```rust
        require!(
            Self::request_matches_finality(&payload_v1.request, finality),
            ProverError::FinalityMismatch.as_ref()
        );
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

**File:** near/omni-prover/mpc-omni-prover/src/tests.rs (L87-101)
```rust
fn test_evm_request() -> EvmRpcRequest {
    EvmRpcRequest {
        tx_id: EvmTxId([0xab; 32]),
        extractors: vec![EvmExtractor::Log { log_index: 0 }],
        finality: EvmFinality::Finalized,
    }
}

fn abs_testnet_evm_request() -> EvmRpcRequest {
    EvmRpcRequest {
        tx_id: abs_testnet_tx_id(),
        extractors: vec![EvmExtractor::Log { log_index: 3 }],
        finality: EvmFinality::Latest,
    }
}
```

**File:** near/omni-prover/mpc-omni-prover/src/tests.rs (L299-310)
```rust
#[test]
fn test_request_matches_finality_abstract_mismatch() {
    let request = ForeignChainRpcRequest::Abstract(abs_testnet_evm_request());
    assert!(!MpcOmniProver::request_matches_finality(
        &request,
        &MpcFinality::Evm(EvmFinality::Finalized)
    ));
    assert!(!MpcOmniProver::request_matches_finality(
        &request,
        &MpcFinality::Evm(EvmFinality::Safe)
    ));
}
```

**File:** near/omni-prover/mpc-omni-prover/src/tests.rs (L472-480)
```rust
fn starknet_sepolia_request() -> StarknetRpcRequest {
    StarknetRpcRequest {
        tx_id: StarknetTxId(hex_to_starknet_felt(
            "0x0592d937f74565b8c42c5603083e5536fdcd8e585b5fef5cd5c2c04b65cd80e5",
        )),
        finality: StarknetFinality::AcceptedOnL2,
        extractors: vec![StarknetExtractor::Log { log_index: 3 }],
    }
}
```
