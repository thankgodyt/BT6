### Title
`MetadataPayload` for `deployToken` Lacks Chain-ID Binding, Enabling Cross-Chain Signature Replay — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `near/omni-types/src/lib.rs`, `starknet/src/bridge_types.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

---

### Summary

The MPC-signed `MetadataPayload` used by `deployToken` across all destination chains (EVM, Starknet, Solana) does not include a chain identifier in the signed data. Because the same `nearBridgeDerivedAddress` (derived from the single MPC key) is used across all EVM chains, a valid `deployToken` signature obtained for one chain (e.g., Ethereum) can be replayed verbatim on every other EVM chain (Arbitrum, Base, Polygon, BNB, HyperEVM, Abstract). This is in direct contrast to `finTransfer`, which explicitly encodes `omniBridgeChainId` in its signed payload.

---

### Finding Description

**Root cause — no chain-id in `MetadataPayload`:**

The NEAR bridge signs a `MetadataPayload` containing only:

```
prefix (PayloadType::Metadata) | token | name | symbol | decimals
```

This is confirmed in all three destination-chain implementations:

- **EVM** (`OmniBridge.sol:142-149`): the Borsh-encoded blob passed to `keccak256` and then to `ECDSA.recover` contains no chain identifier.
- **Starknet** (`bridge_types.cairo:36-44`): `MetadataPayload.to_borsh()` encodes the same five fields with no chain-id.
- **Solana** (`deploy_token.rs:19-26`): `DeployTokenPayload::serialize_for_near()` encodes `IncomingMessageType::Metadata` followed by the four metadata fields, with no chain-id.
- **NEAR origin** (`omni-types/src/lib.rs:696-702`): the `MetadataPayload` struct itself has no chain-id field; `log_metadata_callback` signs `borsh::to_vec(&metadata_payload)` directly.

**Contrast with `finTransfer` — chain-id IS present:**

`OmniBridge.sol:289-309` encodes `omniBridgeChainId` twice (once for the token-address chain slot and once for the recipient chain slot). Starknet's `TransferMessagePayload.to_borsh()` (`bridge_types.cairo:61-84`) likewise encodes `chain_id` in both positions. The developers were clearly aware of the cross-chain replay risk for `finTransfer` and mitigated it there, but left `deployToken` unprotected.

---

### Impact Explanation

**Step 1 — Attacker observes a legitimate `deployToken` call on chain A (e.g., Ethereum).** The relayer submits `(signatureData, MetadataPayload{token, name, symbol, decimals})`. The signature is public on-chain.

**Step 2 — Attacker replays the identical call on chains B, C, D … (Arbitrum, Base, Polygon, BNB, etc.).** Because the signed hash is identical across all EVM chains (same `nearBridgeDerivedAddress`, same payload bytes, no chain discriminator), `ECDSA.recover(hashed, signatureData) == nearBridgeDerivedAddress` passes on every chain.

**Step 3 — Unauthorized bridge-token contracts are deployed and registered.** Each target chain's `nearToEthToken[metadata.token]` and `isBridgeToken` mappings are populated with attacker-triggered deployments. The NEAR bridge did not authorize these deployments for those chains.

**Step 4 — Attacker submits Wormhole VAA proofs of the `DeployToken` events to NEAR.** NEAR's `deploy_token` accepts a `ProverResult::LogMetadata` proof from the foreign chain. The attacker-triggered `DeployToken` events on Arbitrum/Base/etc. are valid Wormhole-observable events. Submitting their VAAs causes NEAR to register the attacker-deployed token addresses as the canonical bridge tokens for those chains.

**Step 5 — Token metadata binding is now attacker-controlled per chain.** Once NEAR registers the attacker-deployed contract as the canonical token for chain B, all subsequent `finTransfer` calls on chain B will mint into that contract. The attacker has forced an unauthorized token-address binding for every replayed chain, constituting token metadata binding confusion and an unauthorized bridge action equivalent to a deployer-role bypass.

Additionally, if the attacker replays before the legitimate relayer reaches a given chain, `ERR_TOKEN_EXIST` permanently blocks the legitimate deployment on that chain.

---

### Likelihood Explanation

**High.** The attack requires only:
1. Observing a public `deployToken` transaction on any one EVM chain (zero privilege required).
2. Submitting the same calldata to the other EVM bridge contracts (permissionless, costs only gas).
3. Optionally submitting Wormhole VAA proofs to NEAR (also permissionless relayer action).

No private keys, admin access, or MPC compromise is needed. Any unprivileged actor — including a competing relayer or a malicious token issuer — can execute this.

---

### Recommendation

Include the destination chain identifier in the `MetadataPayload` signed by the MPC, mirroring the pattern already used in `TransferMessagePayload`/`finTransfer`.

**EVM** (`OmniBridge.sol`):
```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
+   bytes1(omniBridgeChainId),          // bind to this chain
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

**NEAR** (`omni-types/src/lib.rs`):
```rust
pub struct MetadataPayload {
    pub prefix: PayloadType,
+   pub chain_kind: ChainKind,   // destination chain
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}
```

Apply the equivalent fix to Starknet's `MetadataPayload.to_borsh()` and Solana's `DeployTokenPayload::serialize_for_near()`.

---

### Proof of Concept

```
1. NEAR MPC signs MetadataPayload{token="usdc.near", name="USD Coin", symbol="USDC", decimals=6}
   → produces signature S

2. Legitimate relayer calls OmniBridge(Ethereum).deployToken(S, payload)
   → USDC bridge token deployed at 0xAAA on Ethereum ✓

3. Attacker calls OmniBridge(Arbitrum).deployToken(S, payload)   // same S, same payload
   → ECDSA.recover(keccak256(borsh(payload)), S) == nearBridgeDerivedAddress  ✓ (no chain-id in hash)
   → USDC bridge token deployed at 0xBBB on Arbitrum (unauthorized)

4. Attacker calls OmniBridge(Base).deployToken(S, payload)
   → USDC bridge token deployed at 0xCCC on Base (unauthorized)

5. Attacker submits Wormhole VAA of Arbitrum's DeployToken(0xBBB) event to NEAR deploy_token()
   → NEAR registers 0xBBB as canonical USDC address for Arbitrum

6. All future NEAR→Arbitrum USDC transfers finalize into 0xBBB (attacker-chosen contract)
   → Token metadata binding is now attacker-controlled for Arbitrum
```

**Key evidence — signed payload bytes are identical across chains:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L142-149)
```text
        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
            Borsh.encodeString(metadata.token),
            Borsh.encodeString(metadata.name),
            Borsh.encodeString(metadata.symbol),
            bytes1(metadata.decimals)
        );
        bytes32 hashed = keccak256(borshEncoded);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-309)
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
```

**File:** near/omni-types/src/lib.rs (L694-702)
```rust
#[near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct MetadataPayload {
    pub prefix: PayloadType,
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}
```

**File:** starknet/src/bridge_types.cairo (L36-44)
```text
    fn to_borsh(self: @MetadataPayload) -> ByteArray {
        let mut borsh_bytes: ByteArray = Default::default();
        borsh_bytes.append_byte(PayloadType::Metadata.into());
        borsh_bytes.append(@borsh::encode_byte_array(self.token));
        borsh_bytes.append(@borsh::encode_byte_array(self.name));
        borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
        borsh_bytes.append_byte(*self.decimals);
        borsh_bytes
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

**File:** solana/programs/bridge_token_factory/src/state/message/deploy_token.rs (L16-27)
```rust
impl Payload for DeployTokenPayload {
    type AdditionalParams = ();

    fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
        let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
        IncomingMessageType::Metadata.serialize(&mut writer)?;
        self.serialize(&mut writer)?; // borsh encoding
        writer
            .into_inner()
            .map_err(|_| error!(ErrorCode::InvalidArgs))
    }
}
```

**File:** near/omni-bridge/src/lib.rs (L341-351)
```rust
        let metadata_payload = MetadataPayload {
            prefix: PayloadType::Metadata,
            token: token_id.to_string(),
            name: metadata.name,
            symbol: metadata.symbol,
            decimals: metadata.decimals,
        };

        let payload = near_sdk::env::keccak256_array(
            borsh::to_vec(&metadata_payload).near_expect(BridgeError::Borsh),
        );
```
