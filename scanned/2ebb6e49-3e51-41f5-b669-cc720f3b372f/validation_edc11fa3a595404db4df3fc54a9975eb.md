### Title
Missing Contract Address in `finTransfer` Message Hash Enables Cross-Deployment Signature Replay — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
The `finTransfer` function in `OmniBridge.sol` constructs its message hash without including `address(this)`. The hash uses only a custom 1-byte `omniBridgeChainId` (not the actual EVM `block.chainid`) for chain binding. Because the MPC-derived signer key (`nearBridgeDerivedAddress`) is the same across all bridge deployments, any valid `finTransfer` signature can be replayed on any other `OmniBridge` contract deployed on the same chain with the same `omniBridgeChainId`, enabling double-spending of bridged funds.

### Finding Description

In `OmniBridge.sol::finTransfer()`, the `borshEncoded` message hash is assembled as: [1](#0-0) 

The fields hashed are: `PayloadType.TransferMessage`, `destinationNonce`, `originChain`, `originNonce`, `omniBridgeChainId`, `tokenAddress`, `amount`, `omniBridgeChainId` (again for recipient chain), `recipient`, `feeRecipient`, `message`. Neither `address(this)` nor `block.chainid` is included.

The `omniBridgeChainId` is a custom 1-byte `ChainKind` enum value (e.g., `0` for Ethereum, `3` for Arbitrum): [2](#0-1) 

It is **not** the actual EVM `block.chainid`. The signature is verified against `nearBridgeDerivedAddress`, which is the NEAR MPC-derived key — identical across all bridge deployments: [3](#0-2) 

The `completedTransfers` nonce bitmap is per-contract storage. A freshly deployed contract has an empty bitmap, so all previously-issued signatures for any nonce are valid against it.

The same structural flaw exists in the Starknet bridge's `fin_transfer`, where `to_borsh(chain_id)` includes `omni_bridge_chain_id` but not `get_contract_address()`: [4](#0-3) [5](#0-4) 

The EVM `SECURITY.md` explicitly acknowledges that `deployToken` metadata signatures are intentionally chain-agnostic: [6](#0-5) 

However, **no such acknowledgment exists for `finTransfer`**, which carries real user funds and must be strictly domain-separated.

### Impact Explanation

An attacker who has observed any legitimate `finTransfer` transaction (all calldata is public on-chain) can replay the exact same signature and payload on any newly deployed `OmniBridge` contract on the same chain that shares the same `omniBridgeChainId` and `nearBridgeDerivedAddress`. The new contract's `completedTransfers` mapping starts empty, so the nonce check passes, the hash is identical (no `address(this)`), and the signature verification passes. The attacker receives a second disbursement of the same tokens — a direct double-spend of bridged funds.

This is a **Critical** impact: unauthorized minting/unlocking of bridged tokens via cross-deployment signature replay.

### Likelihood Explanation

Moderate. The attack requires a second `OmniBridge` contract to be deployed on the same chain with the same `omniBridgeChainId`. This is a realistic operational scenario: bridge migrations, security-incident redeployments, or parallel bridge instances for different token sets. The attacker requires no special privileges — only access to historical on-chain calldata, which is fully public. Once a second deployment exists, every historical `finTransfer` signature becomes a weapon.

### Recommendation

Include `address(this)` in the `borshEncoded` message hash inside `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
    Borsh.encodeUint64(payload.destinationNonce),
    bytes1(payload.originChain),
    Borsh.encodeUint64(payload.originNonce),
    bytes1(omniBridgeChainId),
+   Borsh.encodeAddress(address(this)),   // bind to this contract
    Borsh.encodeAddress(payload.tokenAddress),
    ...
);
```

Optionally also include `block.chainid` (as a `uint256`) for fork protection. Apply the same fix to the Starknet `fin_transfer` by including `get_contract_address()` in `to_borsh`. The NEAR `sign_transfer` signing path must be updated in parallel to include the destination contract address in `TransferMessagePayload::encode_hashable()`: [7](#0-6) [8](#0-7) 

### Proof of Concept

1. User initiates a NEAR→Ethereum transfer. NEAR MPC signs a `TransferMessagePayload` with `destinationNonce = 42`, `amount = 10,000 USDC`, `recipient = attacker`.
2. Relayer calls `finTransfer` on `OmniBridge` at `0xOLD` (Ethereum, `omniBridgeChainId = 0`). Signature verifies; 10,000 USDC minted to attacker. `completedTransfers[42] = true` on `0xOLD`.
3. Bridge team deploys a new `OmniBridge` at `0xNEW` on Ethereum with the same `omniBridgeChainId = 0` and same `nearBridgeDerivedAddress`. `completedTransfers` is empty.
4. Attacker calls `finTransfer` on `0xNEW` with the identical signature and payload from step 1.
   - `completedTransfers[42]` on `0xNEW` is `false` → nonce check passes.
   - `borshEncoded` hash is identical (no `address(this)`) → `ECDSA.recover` returns `nearBridgeDerivedAddress` → signature check passes.
   - Another 10,000 USDC is minted to attacker.
5. Attacker repeats for every historical `finTransfer` nonce (all public on-chain), draining the new contract.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-313)
```text
        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** near/omni-types/src/lib.rs (L52-83)
```rust
#[repr(u8)]
pub enum ChainKind {
    #[default]
    #[serde(alias = "eth")]
    Eth,
    #[serde(alias = "near")]
    Near,
    #[serde(alias = "sol")]
    Sol,
    #[serde(alias = "arb")]
    Arb,
    #[serde(alias = "base")]
    Base,
    #[serde(alias = "bnb")]
    Bnb,
    #[serde(alias = "btc")]
    Btc,
    #[serde(alias = "zcash")]
    Zcash,
    #[serde(alias = "pol")]
    Pol,
    #[serde(rename = "HlEvm")]
    #[serde(alias = "hlevm")]
    #[strum(serialize = "HlEvm")]
    HyperEvm,
    #[serde(alias = "strk")]
    Strk,
    #[serde(alias = "abs")]
    Abs,
    #[serde(alias = "fogo")]
    Fogo,
}
```

**File:** near/omni-types/src/lib.rs (L684-692)
```rust
impl TransferMessagePayload {
    pub fn encode_hashable(&self) -> Result<Vec<u8>, String> {
        if self.message.is_empty() {
            borsh::to_vec(&TransferMessagePayloadV1::from(self.clone())).map_err(stringify)
        } else {
            borsh::to_vec(self).map_err(stringify)
        }
    }
}
```

**File:** starknet/src/bridge_types.cairo (L61-84)
```text
    fn to_borsh(self: @TransferMessagePayload, chain_id: u8) -> ByteArray {
        let mut borsh_bytes: ByteArray = Default::default();
        borsh_bytes.append_byte(PayloadType::TransferMessage.into());
        borsh_bytes.append(@borsh::encode_u64(*self.destination_nonce));
        borsh_bytes.append_byte(*self.origin_chain);
        borsh_bytes.append(@borsh::encode_u64(*self.origin_nonce));
        borsh_bytes.append_byte(chain_id);
        borsh_bytes.append(@borsh::encode_address(*self.token_address));
        borsh_bytes.append(@borsh::encode_u128(*self.amount));
        borsh_bytes.append_byte(chain_id);
        borsh_bytes.append(@borsh::encode_address(*self.recipient));
        match self.fee_recipient {
            Option::None => { borsh_bytes.append_byte(0); },
            Option::Some(fee_recipient) => {
                borsh_bytes.append_byte(1);
                borsh_bytes.append(@borsh::encode_byte_array(fee_recipient));
            },
        }
        match self.message {
            Option::None => {},
            Option::Some(message) => { borsh_bytes.append(@borsh::encode_byte_array(message)); },
        }
        borsh_bytes
    }
```

**File:** starknet/src/omni_bridge.cairo (L242-254)
```text
        fn fin_transfer(
            ref self: ContractState, signature: Signature, payload: TransferMessagePayload,
        ) {
            assert(!_is_paused(@self, PAUSE_FIN_TRANSFER), 'ERR_FIN_TRANSFER_PAUSED');

            assert(
                !self.is_transfer_finalised(payload.destination_nonce), 'ERR_NONCE_ALREADY_USED',
            );
            _set_transfer_finalised(ref self, payload.destination_nonce);

            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );
```

**File:** evm/SECURITY.md (L10-10)
```markdown
- **`deployToken` signature has no chain ID**: Metadata signatures are intentionally chain-agnostic — one NEAR-side signature deploys the same token on all EVM chains
```

**File:** near/omni-bridge/src/lib.rs (L491-506)
```rust
        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };

        let payload = near_sdk::env::keccak256_array(
            transfer_payload
                .encode_hashable()
                .near_expect(BridgeError::Borsh),
        );
```
