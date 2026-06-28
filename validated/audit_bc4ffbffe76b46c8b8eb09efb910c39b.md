### Title
`mpc-omni-prover` Accepts Abstract Chain (`Abs`) Proofs at `EvmFinality::Latest`, Enabling Chain-Reorganization Double-Spend - (File: `near/omni-prover/mpc-omni-prover/src/lib.rs`)

---

### Summary

The `MpcOmniProver` contract is hardcoded to accept inbound transfer proofs from the Abstract (`Abs`) EVM chain at `EvmFinality::Latest` — the most recently seen block, which has no reorganization protection. If the Abstract chain reorganizes after a relayer submits a proof and NEAR credits the recipient, the original `initTransfer` transaction may no longer exist in the canonical chain. The attacker retains both the NEAR-side tokens and the Abstract-chain tokens, constituting a double-spend of bridged funds.

---

### Finding Description

In `MpcOmniProver::init()`, the finality level for `ChainKind::Abs` is set to `MpcFinality::Evm(EvmFinality::Latest)`: [1](#0-0) 

`EvmFinality::Latest` corresponds to the most recently produced block on the Abstract chain — a block that has not achieved consensus finality and can be reorganized away. This is in direct contrast to `ChainKind::Eth`, which the test fixtures confirm uses `EvmFinality::Finalized`: [2](#0-1) 

The `request_matches_finality` function enforces that the submitted proof's finality level must exactly match the configured level for the chain: [3](#0-2) 

This means any proof submitted for `ChainKind::Abs` **must** use `EvmFinality::Latest` — there is no way to submit a finalized proof for this chain. The MPC network then reads the transaction state at `Latest` and signs the payload. In `verify_callback`, the only check is that the MPC-returned `payload_hash` matches the submitted `sign_payload`: [4](#0-3) 

No block finality re-check occurs after the MPC call. Once the callback succeeds, the `ProverResult::InitTransfer` is returned to the NEAR `omni-bridge` `fin_transfer` function, which mints or releases tokens to the recipient with no further chain-state verification.

---

### Impact Explanation

An attacker who initiates a transfer on the Abstract chain and has it verified at `Latest` finality will receive tokens on NEAR. If the Abstract chain subsequently reorganizes and the original `initTransfer` transaction is excluded from the canonical chain, the attacker's Abstract-chain tokens are effectively returned (the burn/lock never happened in the canonical chain), while the NEAR-side tokens remain credited. This is a direct double-spend of bridged funds — **Critical** impact.

The `finalised_transfers` nonce set on NEAR prevents replay of the same proof, but it does not help here: the attacker already received the tokens in the first (and only) submission. There is no mechanism to reclaim NEAR-side tokens after a source-chain reorg.

---

### Likelihood Explanation

Abstract is an EVM-compatible chain. EVM chains experience reorganizations regularly, particularly 1–2 block reorgs. `EvmFinality::Latest` means even a single-block reorg is sufficient to trigger this. An attacker can time the `initTransfer` call to a period of elevated reorg probability (e.g., during network congestion or a known chain instability event) and submit the proof to NEAR immediately, before the reorg occurs. The attack requires no privileged access — `initTransfer` on the Abstract chain bridge is a public function callable by any token holder: [5](#0-4) 

---

### Recommendation

Change the configured finality for `ChainKind::Abs` from `EvmFinality::Latest` to `EvmFinality::Safe` or `EvmFinality::Finalized` in `MpcOmniProver::init()`:

```rust
// Before (vulnerable):
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));

// After (safe):
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Finalized));
```

`EvmFinality::Finalized` corresponds to a block that has achieved consensus finality and cannot be reorganized. If the Abstract chain does not support `eth_getBlockByNumber("finalized")`, use `EvmFinality::Safe` as a minimum. Document the finality guarantee provided by the Abstract chain and ensure the configured level matches it.

---

### Proof of Concept

1. Attacker holds tokens on the Abstract chain and a NEAR account.
2. Attacker calls `initTransfer` on the Abstract chain `OmniBridge` contract, burning/locking tokens and emitting `InitTransfer` at block N (the `Latest` block).
3. A relayer immediately submits a `MpcVerifyProofArgs` with `EvmFinality::Latest` to `mpc-omni-prover::verify_proof()` on NEAR.
4. `verify_proof` passes `request_matches_finality` (since `Latest == Latest`) and calls `mpc_contract.verify_foreign_transaction` with the `Latest`-finality request.
5. The MPC network reads the Abstract chain at block N, finds the transaction, and returns a signed `VerifyForeignTransactionResponse`.
6. `verify_callback` confirms `payload_hash` matches and returns `ProverResult::InitTransfer`.
7. NEAR `omni-bridge::fin_transfer` mints tokens to the attacker's NEAR account and marks the nonce as used in `finalised_transfers`.
8. The Abstract chain reorganizes: block N is replaced by block N', which does not contain the attacker's `initTransfer`. The attacker's Abstract-chain tokens are restored.
9. Attacker now holds both the original Abstract-chain tokens and the newly minted NEAR tokens — a complete double-spend. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L130-151)
```rust
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

**File:** near/omni-prover/mpc-omni-prover/src/tests.rs (L87-93)
```rust
fn test_evm_request() -> EvmRpcRequest {
    EvmRpcRequest {
        tx_id: EvmTxId([0xab; 32]),
        extractors: vec![EvmExtractor::Log { log_index: 0 }],
        finality: EvmFinality::Finalized,
    }
}
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-381)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
```
