### Title
Insufficient Source-Chain Finality Allows Double-Spend via Sequencer Reorg — (`File: near/omni-prover/mpc-omni-prover/src/lib.rs`)

### Summary
The `MpcOmniProver` contract is hardcoded at initialization to accept bridge proofs at `EvmFinality::Latest` for the Abstract chain and `StarknetFinality::AcceptedOnL2` for Starknet. Both finality levels represent pre-L1-settlement states controlled by centralized sequencers. If a sequencer reorganizes its L2 state after the MPC network has already signed the payload and NEAR has minted tokens, the source-chain lock/burn is undone while the destination-side tokens remain — a direct double-spend.

### Finding Description
In `MpcOmniProver::init()`, two finality levels are hardcoded:

```rust
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
finalities.insert(
    ChainKind::Strk,
    MpcFinality::Starknet(StarknetFinality::AcceptedOnL2),
);
```

`verify_proof()` then enforces that any submitted proof's finality field **exactly matches** the configured value via `request_matches_finality`. This means the prover will only accept proofs at `Latest` for Abstract and `AcceptedOnL2` for Starknet — it cannot accept stronger finality for these chains.

- **`EvmFinality::Latest` (Abstract / ZKsync-based)**: The "latest" block tag refers to the most recent block produced by the centralized Abstract sequencer (Matter Labs). This block has not been proven on Ethereum L1. The sequencer can reorganize it before the ZK proof is submitted to L1.

- **`StarknetFinality::AcceptedOnL2` (Starknet)**: A transaction `AcceptedOnL2` has been accepted by the Starknet sequencer (StarkWare) but has NOT been proven on Ethereum L1. The sequencer can reorganize L2 state before L1 settlement. The stronger level, `AcceptedOnL1`, requires the state to be proven on Ethereum — the test suite itself confirms these are distinct and non-interchangeable.

The `evm_log_to_rlp` conversion function also silently ignores the `removed` field of the `EvmLog` struct (which signals a reorged log), though the primary root cause is the finality configuration.

The attack flow is:
1. Attacker calls `initTransfer` on Abstract or Starknet, locking/burning tokens.
2. The transaction lands in the latest block / is accepted on L2.
3. Any relayer (or the attacker themselves) submits a proof with the matching finality tag to `mpc-omni-prover.verify_proof()`.
4. The MPC network verifies the transaction exists at that finality level and signs the payload.
5. `fin_transfer_callback` on the NEAR bridge mints/unlocks tokens to the recipient.
6. The Abstract/Starknet sequencer reorganizes the block before L1 finalization, reverting the source-chain lock/burn.
7. The attacker holds tokens on both chains.

### Impact Explanation
An attacker who can trigger or anticipate a sequencer reorganization (or who is the sequencer itself) can double-spend bridged assets: tokens are minted on NEAR while the corresponding lock/burn on the source chain is rolled back. This results in unbacked minted tokens on NEAR, directly inflating the bridged token supply and draining the bridge's locked reserves.

### Likelihood Explanation
Both Abstract (ZKsync/Matter Labs sequencer) and Starknet (StarkWare sequencer) use centralized sequencers that have historically reorganized L2 state before L1 proof submission. `AcceptedOnL2` on Starknet is explicitly a pre-finality state — the Starknet documentation distinguishes it from `AcceptedOnL1` precisely because L2-only acceptance is reversible. The attack requires sequencer-level reorganization, which is not a routine user action, but it is a known and documented property of these chains, not a theoretical-only scenario.

### Recommendation
- For **Abstract**: Change the configured finality to `EvmFinality::Finalized` (or at minimum `EvmFinality::Safe`), which corresponds to blocks that have been proven on Ethereum L1.
- For **Starknet**: Change the configured finality to `StarknetFinality::AcceptedOnL1`, which requires the Starknet state to be proven and accepted on Ethereum L1 before the bridge releases funds.
- Additionally, add a check in `evm_log_to_rlp` (or its caller) to reject logs where `removed == true`.

### Proof of Concept

**Root cause — hardcoded insufficient finality in `init()`:** [1](#0-0) 

**Enforcement that only the configured (insufficient) finality is accepted:** [2](#0-1) 

**Test confirming `AcceptedOnL2` and `AcceptedOnL1` are distinct and non-interchangeable (production config uses the weaker one):** [3](#0-2) 

**Test confirming Abstract uses `EvmFinality::Latest` (weakest EVM finality):** [4](#0-3) 

**`evm_log_to_rlp` does not check the `removed` field, accepting reorged logs:** [5](#0-4) 

**Abstract is a ZKsync-based mainnet chain (chainId 2741), confirming it uses a centralized sequencer with pre-L1 finality:** [6](#0-5) 

**NEAR bridge mints/unlocks tokens immediately upon proof acceptance, with no additional finality delay:** [7](#0-6)

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

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L212-232)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L704-746)
```rust
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
    }
```
