### Title
Insufficient Finality Levels in `MpcOmniProver` Enable Double-Spend of Bridged Funds from Abstract and Starknet - (File: `near/omni-prover/mpc-omni-prover/src/lib.rs`)

---

### Summary

`MpcOmniProver::init()` hardcodes `EvmFinality::Latest` for the Abstract chain (`ChainKind::Abs`) and `StarknetFinality::AcceptedOnL2` for Starknet (`ChainKind::Strk`). Both are pre-finality states that can be reorganized before settlement on Ethereum L1. A relayer (or the attacker acting as one) can submit a proof of an `InitTransfer` event from a block that is subsequently reorganized, causing NEAR to mint tokens while the source-chain lock is silently undone — a double-spend of bridged funds.

---

### Finding Description

`MpcOmniProver` is the prover contract used for Abstract and Starknet inbound transfers. Its `init()` function populates the `finalities` map with the following hardcoded values:

```rust
// near/omni-prover/mpc-omni-prover/src/lib.rs, lines 56-61
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
finalities.insert(
    ChainKind::Strk,
    MpcFinality::Starknet(StarknetFinality::AcceptedOnL2),
);
```

`verify_proof()` enforces that the submitted proof's finality field **exactly matches** the configured value:

```rust
// lines 95-98
require!(
    Self::request_matches_finality(&payload_v1.request, finality),
    ProverError::FinalityMismatch.as_ref()
);
```

This means the prover **only accepts** proofs at `Latest` / `AcceptedOnL2` and **rejects** proofs at stronger finality levels (`Finalized`, `Safe`, `AcceptedOnL1`). The configured levels are:

| Chain | Configured Finality | Meaning | Safe? |
|---|---|---|---|
| Abstract (`Abs`) | `EvmFinality::Latest` | Most recent L2 block tip, not settled on Ethereum L1 | No |
| Starknet (`Strk`) | `StarknetFinality::AcceptedOnL2` | Accepted by Starknet sequencer, not proven on Ethereum L1 | No |

The `set_finality` function is `#[private]` (self-call only), so these values cannot be changed by any unprivileged actor — they are the permanent production defaults until an admin governance action changes them.

Once the prover returns a valid `ProverResult`, `fin_transfer_callback()` in `near/omni-bridge/src/lib.rs` mints or releases tokens to the recipient with no additional finality check:

```rust
// near/omni-bridge/src/lib.rs, lines 700-746
pub fn fin_transfer_callback(...) -> PromiseOrValue<Nonce> {
    let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else { ... };
    // ... builds TransferMessage, then mints/releases tokens
}
```

---

### Impact Explanation

An attacker who initiates a transfer on Abstract or Starknet can:

1. Lock/burn tokens on the source chain, emitting an `InitTransfer` event.
2. Immediately submit the proof to NEAR's `fin_transfer()` at `Latest`/`AcceptedOnL2` finality — accepted by the prover.
3. NEAR mints/releases tokens to the attacker's recipient address.
4. The source-chain L2 sequencer reorganizes the block (before L1 settlement), undoing the lock/burn.
5. The attacker now holds tokens on both chains.

This is a direct double-spend of bridged funds. The `finalised_transfers` set prevents replay of the same proof, but it does not prevent the source-chain state from being rolled back after the proof was accepted.

---

### Likelihood Explanation

- **Abstract** is an EVM L2 with a centralized sequencer. `EvmFinality::Latest` blocks have no L1 settlement guarantee and can be reorganized by the sequencer operator or due to L2 bugs.
- **Starknet** uses a centralized sequencer (StarkWare). `AcceptedOnL2` state is not proven on Ethereum L1 and can be reorganized before the STARK proof is submitted and verified on L1. The Starknet documentation explicitly distinguishes `AcceptedOnL2` (sequencer-only) from `AcceptedOnL1` (L1-proven, irreversible).
- The attack window is the time between the `InitTransfer` event and L1 settlement — minutes to hours depending on the chain.
- Any relayer (including the attacker themselves) can submit the proof; no special privilege is required.

---

### Recommendation

1. **Abstract chain**: Change `EvmFinality::Latest` to `EvmFinality::Finalized` (or at minimum `EvmFinality::Safe`) so that proofs are only accepted for blocks that have been finalized on Ethereum L1.
2. **Starknet**: Change `StarknetFinality::AcceptedOnL2` to `StarknetFinality::AcceptedOnL1` so that proofs are only accepted after the STARK proof has been verified on Ethereum L1.
3. Update `request_matches_finality` to accept proofs at **equal or stronger** finality than the configured minimum, rather than requiring an exact match, so that relayers submitting higher-finality proofs are not rejected.

---

### Proof of Concept

1. Attacker calls `initTransfer` on the Abstract bridge contract, locking 1000 USDC. The `InitTransfer` event is included in Abstract block N (at `Latest` finality).
2. Attacker (acting as relayer) immediately calls `fin_transfer()` on the NEAR bridge with a `MpcVerifyProofArgs` containing `finality: EvmFinality::Latest` for block N.
3. `MpcOmniProver::verify_proof()` passes the `request_matches_finality` check (line 95-98) because the configured finality for `ChainKind::Abs` is `EvmFinality::Latest`.
4. The MPC network confirms the event; `verify_callback()` returns a valid `ProverResult::InitTransfer`.
5. `fin_transfer_callback()` mints 1000 USDC-equivalent tokens to the attacker's NEAR address.
6. Before Abstract block N is settled on Ethereum L1, the Abstract sequencer reorganizes the chain, removing block N. The 1000 USDC lock is reversed.
7. Attacker holds 1000 USDC on Abstract and 1000 USDC-equivalent on NEAR.

The same scenario applies to Starknet using `StarknetFinality::AcceptedOnL2` before the STARK proof is submitted to Ethereum L1. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L90-98)
```rust
        let finality = self
            .finalities
            .get(&chain_kind)
            .near_expect(ProverError::UnsupportedChain);

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

**File:** near/omni-bridge/src/lib.rs (L700-746)
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
    }
```

**File:** near/omni-types/src/mpc_types.rs (L1-12)
```rust
use near_mpc_sdk::{
    foreign_chain::starknet::StarknetFinality, near_mpc_contract_interface::types::EvmFinality,
};
use near_sdk::near;

/// Finality enum that supports both EVM and Starknet chains.
#[near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub enum MpcFinality {
    Evm(EvmFinality),
    Starknet(StarknetFinality),
}
```
