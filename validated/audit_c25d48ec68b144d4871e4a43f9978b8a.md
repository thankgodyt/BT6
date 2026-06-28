### Title
`MpcOmniProver` Hardcodes `EvmFinality::Latest` for Abstract Chain, Enabling Double-Spend via Block Reorg — (File: `near/omni-prover/mpc-omni-prover/src/lib.rs`)

---

### Summary

The `MpcOmniProver` contract is hardcoded to accept `EvmFinality::Latest` for the Abstract (`Abs`) chain. `Latest` is the most recent, non-finalized block — it carries no finality guarantee and is susceptible to sequencer-level reorganization. If a reorg occurs on Abstract chain after NEAR has already minted tokens, the attacker recovers their source-chain tokens while retaining the minted NEAR tokens, achieving a double-spend. A compounding issue is that `extract_evm_log` / `evm_log_to_rlp` never check the `EvmLog.removed` field, so even a log explicitly flagged as reorganized-away would be accepted.

---

### Finding Description

In `MpcOmniProver::init()`, the finality map is populated as:

```rust
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
``` [1](#0-0) 

`request_matches_finality` enforces that the submitted proof's finality level exactly matches the configured one:

```rust
(ForeignChainRpcRequest::Ethereum(args) | ForeignChainRpcRequest::Abstract(args),
 MpcFinality::Evm(finality)) => args.finality == *finality,
``` [2](#0-1) 

Because the configured value is `Latest`, only proofs carrying `EvmFinality::Latest` are accepted — and those are the only proofs that will ever pass. The test fixture for Abstract confirms this is the intended production value:

```rust
fn abs_testnet_evm_request() -> EvmRpcRequest {
    EvmRpcRequest { finality: EvmFinality::Latest, ... }
}
``` [3](#0-2) 

By contrast, Ethereum is configured with `EvmFinality::Finalized` (the safe, post-merge finality checkpoint), as confirmed by the Ethereum test fixture: [4](#0-3) 

The secondary defect is in `extract_evm_log` → `evm_log_to_rlp`. The `EvmLog` struct carries a `removed: bool` field (set to `true` by Ethereum-compatible nodes when a log was part of a reorganized-away block). Neither function checks this field before converting the log to RLP and returning it as a valid proof:

```rust
fn extract_evm_log(payload: &ForeignTxSignPayloadV1) -> Result<Vec<u8>, String> {
    // ... pattern-matches EvmLog, calls evm_log_to_rlp — no removed check
}

fn evm_log_to_rlp(evm_log: &EvmLog) -> Result<Vec<u8>, String> {
    let address = Address::from_slice(&evm_log.address.0);
    // uses only address, topics, data — removed field silently ignored
    ...
}
``` [5](#0-4) 

On the NEAR bridge side, `add_fin_transfer` inserts the `TransferId` into `finalised_transfers` to prevent replay of the same proof: [6](#0-5) 

This replay guard is correct but irrelevant to the reorg scenario: the attacker does not need to replay the proof — they only need the source-chain transaction to disappear after NEAR has already finalized the transfer.

---

### Impact Explanation

An attacker who initiates a transfer on Abstract chain at `Latest` finality and successfully gets NEAR to mint tokens can recover their Abstract-chain tokens if the block containing their `initTransfer` is reorganized away. The result is that the attacker holds tokens on both chains simultaneously — a direct double-spend of bridged funds. The `finalised_transfers` nonce guard on NEAR does not mitigate this because the attacker does not replay the proof; they simply benefit from the source-chain state reverting.

---

### Likelihood Explanation

Abstract is a ZK Stack rollup with a centralized sequencer. L2 blocks are not proven on Ethereum L1 until a ZK proof is submitted and verified; until that point, the sequencer can reorganize L2 state. `EvmFinality::Latest` corresponds to the sequencer's most recent block — the state furthest from L1 finality. A sophisticated attacker who can influence or collude with the Abstract sequencer (or exploit a sequencer bug) can trigger a reorg of the block containing their `initTransfer` after NEAR has already minted. Even without sequencer collusion, the window between `Latest` block inclusion and L1 proof verification is non-zero and exploitable under adverse network conditions. The disqualification criteria explicitly excludes only "NEAR validator collusion/reorg/finality failure" — a reorg on the source chain (Abstract) is not excluded.

---

### Recommendation

1. Change the configured finality for `ChainKind::Abs` from `EvmFinality::Latest` to `EvmFinality::Finalized` (or at minimum `EvmFinality::Safe`), matching the treatment of Ethereum:
   ```rust
   finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Finalized));
   ```
2. Add an explicit check for `evm_log.removed` in `extract_evm_log` and reject the proof if `removed == true`:
   ```rust
   if evm_log.removed {
       return Err(ProverError::InvalidProof.to_string());
   }
   ```

---

### Proof of Concept

1. Attacker calls `initTransfer` on the Abstract chain `OmniBridge`, locking/burning tokens. The transaction lands in block `N` (the current `Latest` block).
2. Attacker (acting as relayer) immediately calls `mpc-omni-prover.verify_proof()` on NEAR with a `MpcVerifyProofArgs` whose embedded `ForeignChainRpcRequest::Abstract` carries `finality: EvmFinality::Latest`.
3. `request_matches_finality` passes because the configured finality for `ChainKind::Abs` is `EvmFinality::Latest`.
4. The MPC network's `verify_foreign_transaction` fetches the log from block `N` (currently canonical) and returns a signed `VerifyForeignTransactionResponse`.
5. `verify_callback` validates the payload hash and calls `parse_evm_proof`, returning a valid `ProverResult`.
6. NEAR's `omni-bridge.fin_transfer()` calls `add_fin_transfer` (marks the `TransferId` as finalised) and mints tokens to the attacker on NEAR.
7. The Abstract chain sequencer reorganizes block `N` away (e.g., due to a sequencer restart, bug, or deliberate action). The `initTransfer` transaction no longer exists on Abstract chain; the attacker's tokens are returned.
8. The attacker now holds the full token amount on both Abstract chain and NEAR — a complete double-spend. [1](#0-0) [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L176-232)
```rust
    fn extract_evm_log(payload: &ForeignTxSignPayloadV1) -> Result<Vec<u8>, String> {
        if payload.values.len() != 1 {
            return Err(ProverError::InvalidPayloadValuesLength.to_string());
        }

        let Some(ExtractedValue::EvmExtractedValue(EvmExtractedValue::Log(evm_log))) =
            payload.values.first()
        else {
            return Err(ProverError::InvalidProof.to_string());
        };

        evm_log_to_rlp(evm_log)
    }

    fn parse_starknet_result(
        kind: ProofKind,
        chain_kind: ChainKind,
        payload: &ForeignTxSignPayloadV1,
    ) -> Result<ProverResult, String> {
        if payload.values.len() != 1 {
            return Err(ProverError::InvalidPayloadValuesLength.to_string());
        }

        let Some(ExtractedValue::StarknetExtractedValue(StarknetExtractedValue::Log(starknet_log))) =
            payload.values.first()
        else {
            return Err(ProverError::InvalidProof.to_string());
        };

        let keys: Vec<[u8; 32]> = starknet_log.keys.iter().map(|k| k.0).collect();
        let data: Vec<[u8; 32]> = starknet_log.data.iter().map(|d| d.0).collect();

        parse_starknet_proof(kind, chain_kind, &starknet_log.from_address.0, &keys, &data)
    }
}

fn evm_log_to_rlp(
    evm_log: &near_mpc_sdk::near_mpc_contract_interface::types::EvmLog,
) -> Result<Vec<u8>, String> {
    let address = Address::from_slice(&evm_log.address.0);

    let topics: Vec<B256> = evm_log
        .topics
        .iter()
        .map(|t| B256::from_slice(&t.0))
        .collect();

    let data_str = evm_log.data.strip_prefix("0x").unwrap_or(&evm_log.data);
    let data_bytes = hex::decode(data_str).map_err(|_| ProverError::InvalidProof.to_string())?;

    let log = Log::new_unchecked(address, topics, Bytes::from(data_bytes));

    let mut buf = Vec::new();
    log.encode(&mut buf);

    Ok(buf)
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
