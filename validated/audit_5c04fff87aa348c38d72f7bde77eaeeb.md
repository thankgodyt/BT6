### Title
Caller-Supplied `values` Field in MPC Sign Payload Is Not Cryptographically Bound to the MPC-Verified Request, Enabling Cross-Chain Event Forgery — (`near/omni-prover/mpc-omni-prover/src/lib.rs`)

### Summary
`MpcOmniProver::verify_proof` accepts a caller-supplied `sign_payload` that contains two independent parts: a `request` (sent to the MPC contract for on-chain verification) and a `values` field (the extracted log data used to construct the final `ProverResult`). The MPC contract only receives and hashes the `request`; it never sees `values`. Because the returned `payload_hash` is computed solely from `{request, domain_id, payload_version}`, the equality check `sign_payload.compute_msg_hash() == mpc_response.payload_hash` cannot cryptographically commit to `values`. A malicious relayer can therefore pair any real foreign-chain transaction (satisfying MPC verification) with entirely forged `values` — including a registered factory address and fabricated `InitTransfer` event data — causing the bridge to mint tokens for a transfer that never occurred.

### Finding Description

In `verify_proof` (lines 100–109), only `payload_v1.request` is forwarded to the MPC contract:

```rust
let request_args = VerifyForeignTransactionRequestArgs {
    request: payload_v1.request.clone(),   // values is NOT included
    domain_id: DomainId(FOREIGN_TX_DOMAIN_ID),
    payload_version: ForeignTxPayloadVersion::V1,
};
ext_mpc_contract::ext(self.mpc_contract_id.clone())
    ...
    .verify_foreign_transaction(request_args)
``` [1](#0-0) 

The MPC contract therefore computes `payload_hash` from `{request, domain_id, payload_version}` only. In `verify_callback` (lines 136–141), the prover checks:

```rust
let expected_hash = sign_payload.compute_msg_hash()...;
if expected_hash != mpc_response.payload_hash {
    return Err(ProverError::InvalidPayloadHash.to_string());
}
``` [2](#0-1) 

Because `mpc_response.payload_hash` is derived from data that never included `values`, `compute_msg_hash()` cannot incorporate `values` and still produce a matching digest for any legitimate proof. This is a structural impossibility: `values` is provably outside the MPC-verified commitment.

Immediately after the hash check, the unverified `values` field is used to extract the log that drives the proof result. For EVM chains (Abstract), `extract_evm_log` reads `payload.values[0]` directly:

```rust
let log_entry_data = Self::extract_evm_log(payload_v1)?;
parse_evm_proof(proof_kind, chain_kind, log_entry_data)
``` [3](#0-2) 

`extract_evm_log` reads `evm_log.address`, `evm_log.topics`, and `evm_log.data` verbatim from the caller-supplied payload:

```rust
let log = Log::new_unchecked(address, topics, Bytes::from(data_bytes));
``` [4](#0-3) 

The resulting RLP-encoded log is then decoded by `parse_evm_proof` → `parse_evm_event` → `TryFromLog<Log<InitTransfer>>`, which constructs an `InitTransferMessage` whose `emitter_address`, `token`, `amount`, `recipient`, and `fee` all originate from the forged `values`. [5](#0-4) 

The bridge's `fin_transfer_callback` then validates only that `emitter_address` matches a registered factory — a value the attacker controls through `values`:

```rust
require!(
    self.factories.get(&init_transfer.emitter_address.get_chain())
        == Some(init_transfer.emitter_address),
    BridgeError::UnknownFactory.as_ref()
);
``` [6](#0-5) 

Since factory addresses are public contract state, the attacker simply sets `evm_log.address` to the known Abstract factory address in the forged `values`.

The same flaw applies to Starknet via `parse_starknet_result`, where `starknet_log.from_address` (also from `values`) becomes the `emitter_address`. [7](#0-6) 

### Impact Explanation
A malicious relayer can mint an arbitrary amount of any bridged token on NEAR by submitting a `fin_transfer` call whose `prover_args` contain:
- A valid `request` for any real transaction on Abstract or Starknet (the transaction need not involve the bridge at all — it only needs to satisfy MPC's liveness check).
- Forged `values` encoding a fake `InitTransfer` log with the registered factory address, the attacker's NEAR account as recipient, and an arbitrarily large amount.

The bridge will mint the specified tokens to the attacker's account. This constitutes unauthorized minting and theft of bridged funds — a Critical impact.

### Likelihood Explanation
The `fin_transfer` entry point is accessible to any registered relayer. Relayer applicants and custom relayers are explicitly within scope. The attack requires no special cryptographic capability: the attacker only needs to find any real transaction on Abstract or Starknet that MPC will confirm, then craft the `values` bytes locally. All factory addresses are readable from public contract state. The exploit is deterministic and requires no brute force.

### Recommendation
The `values` field must be cryptographically committed to by the MPC contract before it is trusted. Two concrete approaches:

1. **Include `values` in the MPC request**: Pass the hash of `values` as part of `VerifyForeignTransactionRequestArgs` so the MPC contract's `payload_hash` covers it. The callback can then verify that the `values` hash matches what MPC committed to.
2. **Have MPC extract and return the values itself**: Instead of accepting caller-supplied `values`, have the MPC contract extract the log data from the verified transaction and return it in `VerifyForeignTransactionResponse`. The prover then uses only MPC-returned data, never caller-supplied data.

Until fixed, the MPC prover path (Abstract, Starknet) should be paused.

### Proof of Concept

1. Attacker identifies any confirmed transaction `tx_hash` on Abstract chain (e.g., a simple ETH transfer).
2. Attacker reads the registered Abstract factory address `factory_addr` from the bridge contract's `factories` map.
3. Attacker constructs `sign_payload` as `ForeignTxSignPayload::V1` with:
   - `request = ForeignChainRpcRequest::Abstract({ tx_hash, finality: Latest, ... })` — a valid request MPC will confirm.
   - `values = [ExtractedValue::EvmExtractedValue(EvmExtractedValue::Log(EvmLog { address: factory_addr, topics: [InitTransfer_TOPIC, sender_topic, token_topic, nonce_topic], data: abi_encode(amount=1_000_000e18, fee=0, nativeFee=0, recipient="near:attacker.near", message="") }))]`
4. Attacker calls `bridge.fin_transfer({ chain_kind: Abs, prover_args: borsh(MpcVerifyProofArgs { proof_kind: InitTransfer, sign_payload }) })`.
5. Bridge calls `mpc_prover.verify_proof(sign_payload)`.
6. MPC verifies `request` (the real tx), returns `payload_hash` covering only `request`.
7. `verify_callback`: `compute_msg_hash()` matches `payload_hash` (since `values` is excluded from both). Hash check passes.
8. `extract_evm_log` decodes the forged log; `parse_evm_proof` produces `ProverResult::InitTransfer` with `emitter_address = factory_addr`, `recipient = attacker.near`, `amount = 1_000_000e18`.
9. `fin_transfer_callback` passes the factory check, mints 1,000,000 tokens to `attacker.near`.

### Citations

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L100-109)
```rust
        let request_args = VerifyForeignTransactionRequestArgs {
            request: payload_v1.request.clone(),
            domain_id: DomainId(FOREIGN_TX_DOMAIN_ID),
            payload_version: ForeignTxPayloadVersion::V1,
        };

        ext_mpc_contract::ext(self.mpc_contract_id.clone())
            .with_static_gas(VERIFY_FOREIGN_TX_GAS)
            .with_attached_deposit(ONE_YOCTO)
            .verify_foreign_transaction(request_args)
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L136-141)
```rust
        let expected_hash = sign_payload
            .compute_msg_hash()
            .map_err(|_| ProverError::InvalidPayloadHash.to_string())?;

        if expected_hash != mpc_response.payload_hash {
            return Err(ProverError::InvalidPayloadHash.to_string());
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L149-151)
```rust
            let log_entry_data = Self::extract_evm_log(payload_v1)?;
            parse_evm_proof(proof_kind, chain_kind, log_entry_data)
        }
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L190-209)
```rust
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
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L226-226)
```rust
    let log = Log::new_unchecked(address, topics, Bytes::from(data_bytes));
```

**File:** near/omni-types/src/evm/events.rs (L115-135)
```rust
impl TryFromLog<Log<InitTransfer>> for InitTransferMessage {
    type Error = String;

    fn try_from_log(chain_kind: ChainKind, event: Log<InitTransfer>) -> Result<Self, Self::Error> {
        Ok(Self {
            emitter_address: OmniAddress::new_from_evm_address(
                chain_kind,
                H160(event.address.into()),
            )?,
            origin_nonce: event.data.originNonce,
            token: OmniAddress::new_from_evm_address(chain_kind, H160(event.tokenAddress.into()))?,
            amount: near_sdk::json_types::U128(event.data.amount),
            recipient: event.data.recipient.parse().map_err(stringify)?,
            fee: Fee {
                fee: near_sdk::json_types::U128(event.data.fee),
                native_fee: near_sdk::json_types::U128(event.data.nativeTokenFee),
            },
            sender: OmniAddress::new_from_evm_address(chain_kind, H160(event.data.sender.into()))?,
            msg: event.data.message,
        })
    }
```

**File:** near/omni-bridge/src/lib.rs (L708-713)
```rust
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );
```
