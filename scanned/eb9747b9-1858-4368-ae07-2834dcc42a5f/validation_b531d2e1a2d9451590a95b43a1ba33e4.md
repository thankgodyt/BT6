### Title
Insecure Default Finality (`EvmFinality::Latest`) in `MpcOmniProver` Enables Proof Acceptance for Unfinalized Blocks, Risking Unauthorized Token Minting via Chain Reorg - (File: `near/omni-prover/mpc-omni-prover/src/lib.rs`)

### Summary

`MpcOmniProver::init` hardcodes `EvmFinality::Latest` as the finality level for the Abstract chain (`ChainKind::Abs`) and `StarknetFinality::AcceptedOnL2` for Starknet. `EvmFinality::Latest` is the weakest possible EVM finality — it instructs the MPC network to read state from the tip of the chain with zero confirmation depth. Because `request_matches_finality` enforces an exact equality check, the contract will only accept proofs carrying this insecure finality tag, permanently locking in the unsafe default. A relayer (including a malicious one) can submit a bridge proof for a transaction in the latest unfinalized block; if that block is subsequently reorganized, the NEAR bridge has already minted tokens against a transaction that no longer exists on the canonical chain.

### Finding Description

In `MpcOmniProver::init`:

```rust
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
finalities.insert(
    ChainKind::Strk,
    MpcFinality::Starknet(StarknetFinality::AcceptedOnL2),
);
```

`EvmFinality::Latest` is the EVM JSON-RPC `"latest"` tag — the chain tip, subject to reorganization. There is no block-depth requirement whatsoever. This is the direct analog of `minBlockHeight: 0` in the external report.

`request_matches_finality` performs a strict equality check:

```rust
(ForeignChainRpcRequest::Ethereum(args) | ForeignChainRpcRequest::Abstract(args),
 MpcFinality::Evm(finality)) => args.finality == *finality,
```

This means the contract will **reject** any proof that uses a safer finality level (`Safe` or `Finalized`) for the Abstract chain, and will **only accept** proofs tagged `Latest`. The insecure setting is not merely a default that can be overridden by a careful relayer — it is the only accepted value.

The `set_finality` function is marked `#[private]`, meaning it can only be invoked as a self-callback from the contract, not by any admin key directly. There is no admin-callable setter to raise the finality level without a contract upgrade.

For Starknet, `AcceptedOnL2` means the transaction is accepted by the StarkWare sequencer but not yet proven on Ethereum L1. L2 state can be reorganized before L1 settlement.

### Impact Explanation

A relayer submits `verify_proof` with a `ForeignChainRpcRequest::Abstract` payload carrying `EvmFinality::Latest`. The MPC network reads the Abstract chain at the current tip and returns a valid `VerifyForeignTransactionResponse`. The bridge's `fin_transfer` callback receives a valid `ProverResult` and mints bridged tokens on NEAR. If the Abstract chain subsequently reorganizes that block (naturally or via a targeted short-range reorg), the source-chain lock transaction is gone, but the NEAR-side mint has already been finalized. The attacker retains both the original source-chain tokens (returned by the reorg) and the newly minted NEAR-side tokens — a double-spend / unauthorized minting of bridged funds.

### Likelihood Explanation

Abstract is a ZK-rollup L2 built on Ethereum. Its sequencer produces blocks that are not immediately finalized on L1. The "latest" block on Abstract can be reorganized at the sequencer level before the ZK proof is posted to Ethereum. A relayer (which can be any public caller of `fin_transfer` on the bridge) can race to submit a proof immediately after a deposit transaction appears in the mempool/latest block, before finality is reached. No special privilege is required beyond being a relayer. The attack is economically motivated for any transfer large enough to cover the cost of inducing or waiting for a reorg.

### Recommendation

1. Change the default finality for `ChainKind::Abs` from `EvmFinality::Latest` to `EvmFinality::Finalized` (or at minimum `EvmFinality::Safe`), matching the approach used for `ChainKind::Eth`.
2. Change the default finality for `ChainKind::Strk` from `StarknetFinality::AcceptedOnL2` to `StarknetFinality::AcceptedOnL1` to require Ethereum L1 settlement.
3. Add an admin-callable (DAO-gated) `set_finality` function so the finality level can be adjusted without a full contract upgrade.
4. Add a compile-time or init-time assertion that rejects `EvmFinality::Latest` for any chain that holds real user funds.

### Proof of Concept

1. Deploy `MpcOmniProver` via `init(mpc_contract_id)`. The contract now has `finalities[Abs] = EvmFinality::Latest`.
2. Attacker deposits tokens into the Abstract chain bridge contract. The deposit transaction lands in block N (latest).
3. Relayer (or attacker acting as relayer) immediately calls `verify_proof` with a `MpcVerifyProofArgs` whose `sign_payload` contains `ForeignChainRpcRequest::Abstract(EvmRpcRequest { finality: EvmFinality::Latest, ... })`.
4. `request_matches_finality` passes (Latest == Latest). The MPC cross-contract call to `verify_foreign_transaction` succeeds because the transaction exists in the current latest block.
5. `verify_callback` returns a valid `ProverResult`. The bridge mints tokens on NEAR to the attacker's recipient address.
6. Block N is reorganized (sequencer reorg or short-range reorg). The deposit transaction is removed from the canonical chain; the attacker's source-chain tokens are effectively returned.
7. Attacker now holds both the source-chain tokens and the NEAR-minted tokens — double-spend complete.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

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
