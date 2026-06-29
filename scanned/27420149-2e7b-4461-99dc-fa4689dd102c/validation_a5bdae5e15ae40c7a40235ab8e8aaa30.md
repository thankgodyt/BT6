### Title
Non-Finalized Proof Acceptance via `EvmFinality::Latest` Enables Reorg-Based Unauthorized Minting on NEAR — (File: `near/omni-prover/mpc-omni-prover/src/lib.rs`)

---

### Summary

The `mpc-omni-prover` contract is hardcoded to accept proofs for the Abstract chain (`ChainKind::Abs`) at `EvmFinality::Latest` — the weakest EVM finality level, representing only the most recently seen block with no confirmation depth or BFT-commit guarantee. If the Abstract chain experiences a reorg after the MPC network has attested to a transaction at `Latest` finality, a relayer can submit that attestation to the NEAR bridge and cause it to mint bridged tokens on NEAR for a transfer that was subsequently erased from the canonical Abstract chain. The bridge has no mechanism to detect or reverse this after the fact.

---

### Finding Description

In `near/omni-prover/mpc-omni-prover/src/lib.rs`, the prover's constructor hardcodes the finality level for the Abstract chain:

```rust
// near/omni-prover/mpc-omni-prover/src/lib.rs:55-67
pub fn init(mpc_contract_id: AccountId) -> Self {
    let mut finalities = HashMap::new();
    finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));  // ← non-finalized
    finalities.insert(
        ChainKind::Strk,
        MpcFinality::Starknet(StarknetFinality::AcceptedOnL2),
    );
    ...
}
```

`EvmFinality::Latest` instructs the MPC network to read and sign the transaction state from the most recent block, with no confirmation depth. This is explicitly weaker than `EvmFinality::Safe` (~64 blocks) or `EvmFinality::Finalized` (~96 blocks / post-merge checkpoint).

The `verify_proof` function enforces that the submitted proof's finality matches the configured level:

```rust
// near/omni-prover/mpc-omni-prover/src/lib.rs:95-98
require!(
    Self::request_matches_finality(&payload_v1.request, finality),
    ProverError::FinalityMismatch.as_ref()
);
```

This check correctly rejects proofs that claim a stronger finality than `Latest`, but it does not protect against the scenario where the MPC network legitimately attests to a `Latest`-finality transaction that is subsequently reorganized out of the canonical chain.

In `verify_callback`, the only check performed is that the MPC-returned `payload_hash` matches the submitted `sign_payload`:

```rust
// near/omni-prover/mpc-omni-prover/src/lib.rs:136-142
let expected_hash = sign_payload
    .compute_msg_hash()
    .map_err(|_| ProverError::InvalidPayloadHash.to_string())?;

if expected_hash != mpc_response.payload_hash {
    return Err(ProverError::InvalidPayloadHash.to_string());
}
```

There is no post-reorg invalidation path. Once `fin_transfer_callback` in the main bridge contract inserts the `TransferId` into `finalised_transfers`, the transfer is permanently recorded as complete:

```rust
// near/omni-bridge/src/lib.rs:2226-2234
fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
    let storage_usage = env::storage_usage();
    require!(
        self.finalised_transfers.insert(transfer_id),
        BridgeError::TransferAlreadyFinalised.as_ref()
    );
    ...
}
```

The `finalised_transfers` set prevents replay of the same `origin_nonce`, but it cannot undo a minting that already occurred against a transaction that was later reorganized away.

---

### Impact Explanation

If the Abstract chain reorgs after the MPC network has attested to a `Latest`-finality `InitTransfer` event:

1. The original token lock on Abstract is erased — the attacker's tokens are returned or never actually locked on the canonical chain.
2. The NEAR bridge has already minted the corresponding bridged tokens on NEAR.
3. The attacker holds tokens on both chains simultaneously.

This constitutes **unauthorized minting / double-spending of bridged funds** — a critical impact under the allowed scope.

---

### Likelihood Explanation

The attack requires a reorg on the Abstract chain (HyperLiquid EVM) at `Latest` finality. The root cause is the bridge's own design choice to accept `EvmFinality::Latest` rather than `EvmFinality::Safe` or `EvmFinality::Finalized`. Whether HyperLiquid's consensus provides instant BFT finality (making `Latest ≈ Finalized`) or whether natural short reorgs are possible determines the practical exploitability. The bridge code itself does not verify or enforce any confirmation depth beyond what the MPC network observes at the moment of attestation. If the Abstract chain's RPC layer exposes a `finalized` tag, the correct mitigation is to use it; if not, a minimum confirmation count should be enforced at the MPC layer. The fact that the test fixture `abs_testnet_evm_request()` also uses `EvmFinality::Latest` confirms this is the intended production configuration, not a test artifact.

---

### Recommendation

Change the Abstract chain finality configuration from `EvmFinality::Latest` to `EvmFinality::Finalized` (or at minimum `EvmFinality::Safe`) if the Abstract chain's RPC supports these tags. If the chain's consensus provides instant finality and the `finalized` tag is unavailable, document this explicitly and verify with the chain team that `Latest` is equivalent to finalized in their consensus model. Do not rely on the assumption that "latest" is safe without an explicit guarantee from the chain's consensus protocol.

---

### Proof of Concept

1. Attacker calls `initTransfer` on the Abstract chain OmniBridge contract, locking tokens. The transaction lands in block N (the current `latest` block).
2. A relayer (or the attacker acting as a relayer) immediately calls `fin_transfer` on the NEAR bridge with `chain_kind = ChainKind::Abs` and a `MpcVerifyProofArgs` referencing the Abstract chain transaction at `EvmFinality::Latest`.
3. `mpc-omni-prover.verify_proof` passes the finality check (request finality == `Latest` == configured finality) and calls `mpc_contract.verify_foreign_transaction`.
4. The MPC network reads the transaction from block N at `Latest` finality, finds the `InitTransfer` log, and returns a signed `payload_hash`.
5. `verify_callback` confirms `SHA-256(borsh(sign_payload)) == payload_hash` and returns `ProverResult::InitTransfer`.
6. `fin_transfer_callback` mints bridged tokens to the recipient on NEAR and inserts the `TransferId` into `finalised_transfers`.
7. The Abstract chain reorgs: block N is replaced by a competing fork that does not include the `initTransfer` transaction. The attacker's tokens on Abstract are returned.
8. The attacker now holds the original tokens on Abstract and the minted bridged tokens on NEAR — net gain equal to the full transfer amount. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L136-142)
```rust
        let expected_hash = sign_payload
            .compute_msg_hash()
            .map_err(|_| ProverError::InvalidPayloadHash.to_string())?;

        if expected_hash != mpc_response.payload_hash {
            return Err(ProverError::InvalidPayloadHash.to_string());
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

**File:** near/omni-prover/mpc-omni-prover/src/tests.rs (L95-101)
```rust
fn abs_testnet_evm_request() -> EvmRpcRequest {
    EvmRpcRequest {
        tx_id: abs_testnet_tx_id(),
        extractors: vec![EvmExtractor::Log { log_index: 3 }],
        finality: EvmFinality::Latest,
    }
}
```
