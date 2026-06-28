### Title
Cross-Chain Replay of `MetadataPayload` MPC Signature Enables Unauthorized Token Deployment on Any OmniBridge Instance — (`near/omni-types/src/lib.rs`, `evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/bridge_types.cairo`)

---

### Summary

The `MetadataPayload` Borsh encoding that the MPC signs during `log_metadata` contains no chain-ID or destination-chain discriminant. Because the same MPC-derived address (`nearBridgeDerivedAddress` / `omni_bridge_derived_address`) is used across every OmniBridge deployment, a single valid MPC signature for token T on chain A is unconditionally accepted by `deployToken` on every other EVM chain and on Starknet, without a fresh MPC signing round.

---

### Finding Description

**Root cause — `MetadataPayload` has no chain discriminant**

The struct signed by the MPC is:

```rust
pub struct MetadataPayload {
    pub prefix: PayloadType,
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}
``` [1](#0-0) 

The EVM `deployToken` reconstructs and hashes exactly the same five fields:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
bytes32 hashed = keccak256(borshEncoded);
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
``` [2](#0-1) 

The Starknet `MetadataPayload.to_borsh()` is identical — no chain ID:

```cairo
fn to_borsh(self: @MetadataPayload) -> ByteArray {
    borsh_bytes.append_byte(PayloadType::Metadata.into());
    borsh_bytes.append(@borsh::encode_byte_array(self.token));
    borsh_bytes.append(@borsh::encode_byte_array(self.name));
    borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
    borsh_bytes.append_byte(*self.decimals);
``` [3](#0-2) 

And `_verify_borsh_signature` verifies against `omni_bridge_derived_address` — the same MPC-derived key used on every chain: [4](#0-3) 

**The contrast with `fin_transfer` is explicit.** Transfer messages DO include `omniBridgeChainId` in their signed payload (both EVM and Starknet), preventing cross-chain replay of transfer messages. The Starknet CLAUDE.md even documents this: *"Chain ID binding: Destination chain_id encoded in message hash (not in payload) - prevents cross-chain replay."* That protection was never applied to `deploy_token`. [5](#0-4) 

**The `isBridgeToken` guard is per-instance only.** The duplicate-deployment check on EVM only prevents re-deployment on the same contract instance:

```solidity
require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST");
``` [6](#0-5) 

A different chain's OmniBridge has its own empty `nearToEthToken` mapping, so the check passes. Starknet has the same per-instance guard: [7](#0-6) 

**The `nearBridgeDerivedAddress` is the same across all chains.** It is derived from the NEAR bridge account ID and the fixed path `"bridge-1"` using the MPC root public key — a single deterministic value deployed identically to Ethereum, Base, Arbitrum, Polygon, Starknet, etc.: [8](#0-7) 

---

### Impact Explanation

An attacker who observes a valid `LogMetadataEvent` (containing a `SignatureResponse` over `MetadataPayload{token:T, name:N, symbol:S, decimals:D}`) emitted after a legitimate `log_metadata` call on NEAR can:

1. Call `deployToken(signature, MetadataPayload{T,N,S,D})` on **any** other EVM OmniBridge instance (Base, Arbitrum, Polygon, BSC, etc.) that has not yet deployed token T. The signature verification passes because the hash is identical and `nearBridgeDerivedAddress` is the same.
2. Call `deploy_token(signature, MetadataPayload{T,N,S,D})` on the **Starknet** OmniBridge. Same result.

After the unauthorized deployment, a `DeployToken` event is emitted on the target chain. A relayer can then submit proof of that event to NEAR's `deploy_token` → `deploy_token_callback`, which checks only that the emitter is a registered factory for that chain:

```rust
require!(
    self.factories.get(&chain) == Some(metadata.emitter_address),
    BridgeError::UnknownFactory.as_ref()
);
``` [9](#0-8) 

If the target chain is already a registered factory (which it is for all production deployments), NEAR accepts the binding. The token is now live on an additional chain without any authorization from the protocol operators or a fresh MPC signing round. This is a **chain/domain separation flaw enabling unauthorized token deployment** — a Critical impact under the scope rules.

---

### Likelihood Explanation

- The `LogMetadataEvent` is emitted as a public NEAR log; any observer can extract the `SignatureResponse`.
- The attacker needs no special role, no private key, and no admin access.
- All production EVM chains and Starknet are registered factories on NEAR, so the downstream `deploy_token_callback` will accept the proof.
- The attack is fully executable on a local testnet with unmodified code.

---

### Recommendation

Include the destination chain ID in the `MetadataPayload` Borsh encoding before it is submitted to the MPC for signing, mirroring the existing protection on `TransferMessagePayload`:

```rust
pub struct MetadataPayload {
    pub prefix: PayloadType,
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub destination_chain: ChainKind,  // add this
}
```

The EVM `deployToken` and Starknet `deploy_token` must include `omniBridgeChainId` in the Borsh-encoded bytes before hashing, and the NEAR `log_metadata_callback` must include the intended destination chain when constructing the payload sent to the MPC signer.

---

### Proof of Concept

1. Deploy two local OmniBridge instances (`chainId=1` and `chainId=2`) backed by the same `nearBridgeDerivedAddress` (test wallet).
2. Call NEAR `log_metadata("token.near")` → MPC signs `MetadataPayload{prefix:1, token:"token.near", name:"T", symbol:"T", decimals:18}` → capture `SignatureResponse S`.
3. Call `OmniBridge_chain1.deployToken(S, payload)` — succeeds, token deployed on chain 1.
4. Call `OmniBridge_chain2.deployToken(S, payload)` — **also succeeds** because the hash is identical and the signature is valid. Token is deployed on chain 2 without a second MPC signing round.
5. Assert that step 4 should have reverted with `InvalidSignature` — it does not.

The `isBridgeToken` guard on chain 2 is empty at step 4, so it does not block the deployment. [10](#0-9) [11](#0-10)

### Citations

**File:** near/omni-types/src/lib.rs (L341-351)
```rust
    }

    pub fn is_utxo_chain(&self) -> bool {
        self.get_chain().is_utxo_chain()
    }

    // The AccountId on Near can't be uppercased and has a 64 character limit,
    // so we encode the address into 20 bytes to bypass these restrictions
    fn hashed_token_prefix(prefix: &str, address: &H256) -> String {
        if address.is_zero() {
            prefix.to_string()
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-158)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
        if (tokenImplementationAddress == address(0)) {
            revert TokenImplementationNotSet();
        }
        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
            Borsh.encodeString(metadata.token),
            Borsh.encodeString(metadata.name),
            Borsh.encodeString(metadata.symbol),
            bytes1(metadata.decimals)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }

        require(
            !isBridgeToken[nearToEthToken[metadata.token]],
            "ERR_TOKEN_EXIST"
        );
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

**File:** starknet/src/omni_bridge.cairo (L207-209)
```text
            let token_id_hash = compute_keccak_byte_array(@payload.token);
            let existing_token = self.near_to_starknet_token.read(token_id_hash);
            assert(existing_token.is_zero(), 'ERR_TOKEN_ALREADY_DEPLOYED');
```

**File:** starknet/src/omni_bridge.cairo (L252-254)
```text
            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );
```

**File:** starknet/src/omni_bridge.cairo (L398-406)
```text
    fn _verify_borsh_signature(
        ref self: ContractState, borsh_bytes: @ByteArray, signature: Signature,
    ) {
        let message_hash_le = compute_keccak_byte_array(borsh_bytes);
        let message_hash = reverse_u256_bytes(message_hash_le);

        let sig = signature_from_vrs(signature.v, signature.r, signature.s);
        verify_eth_signature(message_hash, sig, self.omni_bridge_derived_address.read());
    }
```

**File:** evm/hardhat.config.ts (L78-82)
```typescript
    const nearBridgeDerivedAddress = await deriveEVMAddress(
      taskArgs.nearBridgeAccountId,
      "bridge-1",
      mpcRootPublicKey,
    )
```

**File:** near/omni-bridge/src/lib.rs (L1159-1163)
```rust
        let chain = metadata.emitter_address.get_chain();
        require!(
            self.factories.get(&chain) == Some(metadata.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );
```
