### Title
`MpcOmniProver` hardcodes `EvmFinality::Latest` for Abstract chain and `StarknetFinality::AcceptedOnL2` for Starknet, enabling reorg-based double-spend of bridged funds — (File: `near/omni-prover/mpc-omni-prover/src/lib.rs`)

---

### Summary

`MpcOmniProver::init()` permanently sets the finality level for Abstract chain (`ChainKind::Abs`) to `EvmFinality::Latest` and for Starknet (`ChainKind::Strk`) to `StarknetFinality::AcceptedOnL2`. Both are pre-finality states that are subject to sequencer-level reorgs. Because `verify_proof()` enforces that every incoming proof's finality field must exactly match the stored value, all Abstract and Starknet proofs are structurally required to use these weak finality levels. A user who deposits on Abstract chain or Starknet can obtain a valid MPC-signed proof before the source-chain block is finalized, claim bridged tokens on NEAR, and then benefit from a sequencer reorg that erases the original deposit — resulting in theft of bridge funds.

---

### Finding Description

In `MpcOmniProver::init()`, two finality levels are hardcoded:

```rust
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
finalities.insert(
    ChainKind::Strk,
    MpcFinality::Starknet(StarknetFinality::AcceptedOnL2),
);
``` [1](#0-0) 

`verify_proof()` then enforces that the caller-supplied proof's finality field must exactly equal the stored value, rejecting anything stronger:

```rust
require!(
    Self::request_matches_finality(&payload_v1.request, finality),
    ProverError::FinalityMismatch.as_ref()
);
``` [2](#0-1) 

`request_matches_finality` performs a strict equality check — `args.finality == *finality` — so a proof submitted with `EvmFinality::Finalized` for Abstract chain is rejected, and only `EvmFinality::Latest` is accepted: [3](#0-2) 

The only escape valve, `set_finality`, is marked `#[private]`, meaning NEAR SDK enforces `predecessor_account_id == current_account_id`. No method in the contract triggers a self-call to `set_finality`, so the finality values are effectively immutable without a contract upgrade: [4](#0-3) 

**Abstract chain** (`ChainKind::Abs`, chainId 2741) is a ZKsync-based EVM L2 (`zksync: true` in the hardhat config): [5](#0-4) 

On ZKsync-based L2s, `Latest` refers to the most recently produced sequencer block, which has not yet been proven or settled on Ethereum L1. The sequencer can reorg its own blocks before L1 settlement. `EvmFinality::Latest` is explicitly contrasted with `EvmFinality::Finalized` and `EvmFinality::Safe` in the test suite, where Ethereum mainnet proofs are required to use `Finalized`: [6](#0-5) 

**Starknet** (`ChainKind::Strk`) uses `StarknetFinality::AcceptedOnL2`, meaning the transaction is accepted by the Starknet sequencer but not yet proven on Ethereum L1. `AcceptedOnL1` (L1-settled) is the stronger alternative and is used in the Starknet test fixture for Ethereum mainnet: [7](#0-6) 

---

### Impact Explanation

**Critical.** An attacker who deposits tokens on Abstract chain or Starknet can:

1. Initiate a deposit on Abstract chain (or Starknet) — the deposit event is included in a `Latest` (unfinalized) L2 block.
2. Call `verify_proof()` on `MpcOmniProver` with `EvmFinality::Latest`. The MPC network reads the event from the latest block and signs the payload.
3. Submit the MPC-signed proof to the NEAR bridge locker, which mints bridged tokens on NEAR.
4. The Abstract chain sequencer reorgs the block containing the deposit (before L1 settlement). The deposit transaction is erased from the canonical chain.
5. The attacker retains both the original tokens on Abstract chain (deposit never happened on the canonical chain) and the minted tokens on NEAR.

This is a direct double-spend / theft of bridge funds. The NEAR bridge has no mechanism to reverse a completed mint after a source-chain reorg.

---

### Likelihood Explanation

**High.** Abstract chain is a ZKsync-based L2 where sequencer-level reorgs before L1 proof submission are an inherent property of the architecture. The window between a `Latest` block and L1 finalization can be minutes to hours. Starknet sequencer reorgs before L1 proof are similarly documented. A sophisticated attacker can deliberately time the proof submission to exploit this window. The attack requires no privileged access — any bridge user can call `verify_proof()` with a `Latest`-finality proof.

---

### Recommendation

1. Change `ChainKind::Abs` finality from `EvmFinality::Latest` to `EvmFinality::Finalized` (or at minimum `EvmFinality::Safe`), matching the treatment of Ethereum mainnet.
2. Change `ChainKind::Strk` finality from `StarknetFinality::AcceptedOnL2` to `StarknetFinality::AcceptedOnL1`, requiring L1 settlement before a Starknet proof is accepted.
3. Make `set_finality` callable by a privileged admin role (e.g., DAO) rather than only by the contract itself, so finality levels can be adjusted without a full contract upgrade.

---

### Proof of Concept

```
// Attacker flow for Abstract chain:

// Step 1: Deposit 1000 USDC on Abstract chain (ZKsync L2, chainId 2741)
//   → InitTransfer event emitted in block N (Latest, not yet proven on L1)

// Step 2: Construct MpcVerifyProofArgs with:
//   sign_payload.request = ForeignChainRpcRequest::Abstract(EvmRpcRequest {
//       finality: EvmFinality::Latest,   // matches stored finality → passes require!()
//       tx_id: <deposit_tx_hash>,
//       extractors: [Log { log_index: <deposit_log_index> }],
//   })

// Step 3: Call mpc_omni_prover.verify_proof(borsh(args))
//   → verify_proof() passes the finality check (Latest == Latest)
//   → MPC network reads the event from block N (Latest) and signs the payload
//   → verify_callback() succeeds, returns ProverResult::InitTransfer

// Step 4: Submit ProverResult to NEAR bridge locker
//   → NEAR bridge mints 1000 bridged USDC to attacker's NEAR account

// Step 5: Abstract chain sequencer reorgs block N before L1 proof submission
//   → Deposit transaction is removed from canonical chain
//   → Attacker's 1000 USDC is returned / never actually locked

// Result: Attacker holds 1000 USDC on Abstract chain + 1000 bridged USDC on NEAR
//         Bridge escrow is undercollateralized by 1000 USDC
```

The root cause is the hardcoded `EvmFinality::Latest` at: [8](#0-7) 

and `StarknetFinality::AcceptedOnL2` at: [9](#0-8)

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

**File:** evm/hardhat.config.ts (L548-555)
```typescript
    abstractMainnet: {
      omniChainId: 11,
      chainId: 2741,
      url: "https://api.mainnet.abs.xyz",
      ethNetwork: "mainnet",
      zksync: true,
      accounts: [`${EVM_PRIVATE_KEY}`],
    },
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

**File:** near/omni-prover/mpc-omni-prover/src/tests.rs (L103-108)
```rust
fn test_starknet_request() -> StarknetRpcRequest {
    StarknetRpcRequest {
        tx_id: StarknetTxId(StarknetFelt([0xcc; 32])),
        finality: StarknetFinality::AcceptedOnL1,
        extractors: vec![StarknetExtractor::Log { log_index: 0 }],
    }
```
