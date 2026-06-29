### Title
Stale `MetadataPayload` Signatures Remain Valid After `set_metadata`, Enabling Foreign-Chain Token Deployment With Incorrect Decimals — (`near/omni-token/src/lib.rs`, `near/omni-bridge/src/lib.rs`)

---

### Summary

The `MetadataPayload` signed by MPC contains no nonce, timestamp, or version field. Once a signature is emitted as an on-chain event, it is valid forever. If the token's metadata (especially `decimals`) is legitimately updated via `set_metadata` after a signature has been produced, any observer can replay the old signed payload to deploy the token on a foreign chain (EVM, Starknet) that has not yet received the token, using the stale metadata. The resulting decimal mismatch causes permanent amount-normalization errors for all transfers on that chain.

---

### Finding Description

**Step 1 — `MetadataPayload` has no replay-prevention field.** [1](#0-0) 

The struct contains only `prefix`, `token`, `name`, `symbol`, `decimals`. There is no nonce, block height, timestamp, or version. A signature over this struct is valid indefinitely.

**Step 2 — `log_metadata_callback` signs the payload and emits it publicly.** [2](#0-1) 

The signed `MetadataPayload` is emitted as a NEAR event log. Anyone monitoring the chain can capture it.

**Step 3 — `set_metadata` on the OmniToken freely updates name, symbol, and decimals.** [3](#0-2) 

The only guard is `assert_controller()`. There is no check that a `MetadataPayload` has already been signed, no invalidation of prior signatures, and no version bump.

**Step 4 — EVM `deployToken` has no nonce check on metadata signatures.** [4](#0-3) 

The only replay guard is `!isBridgeToken[nearToEthToken[metadata.token]]`, which only prevents deploying the *same token on the same chain* twice. It does not prevent deploying on a *different chain* that has not yet received the token, using a *stale* signed payload.

**Step 5 — The SECURITY.md explicitly confirms signatures are chain-agnostic.** [5](#0-4) 

"Metadata signatures are intentionally chain-agnostic — one NEAR-side signature deploys the same token on all EVM chains." This design means a stale signature is equally valid on every EVM chain.

**Step 6 — Starknet `deploy_token` has the same gap.** [6](#0-5) 

Same pattern: signature verified, then `existing_token.is_zero()` checked. No nonce on the metadata signature.

---

### Impact Explanation

When the NEAR token's `decimals` is changed from 18 to 6 (or vice versa) after a signature has been produced, an attacker deploys the token on a new chain using the old signed payload. The bridge stores `token_decimals` at deployment time. All subsequent `sign_transfer` calls for that chain use the stale decimals for normalization: [7](#0-6) 

A 10^12 factor error in `normalize_amount` means users receive either 10^12× too many or too few tokens on the affected chain. This is a permanent, unrecoverable state for every transfer routed through that chain's token address.

---

### Likelihood Explanation

- `log_metadata` is permissionless; signatures are emitted publicly and can be captured by any observer.
- Metadata updates (especially decimal corrections during token migration or rebranding) are a documented, legitimate DAO operation.
- The window of vulnerability is any chain where the token has not yet been deployed at the time of the metadata update.
- No admin compromise is required; the attacker only needs the publicly emitted signed event and the ability to call `deployToken` on the target chain.

---

### Recommendation

1. **Add a monotonic `metadata_version` counter** to `OmniToken` state. Include it in `MetadataPayload`. Increment it on every `set_metadata` call. The EVM/Starknet `deployToken` should reject payloads whose version is not the current one (requires a NEAR view call or an on-chain registry).
2. **Alternatively, add a nonce or block-height field** to `MetadataPayload` and have `deployToken` reject payloads older than a configurable window.
3. **At minimum**, document that `set_metadata` must never be called after `log_metadata` has been invoked for a token that has not yet been deployed on all target chains, and enforce this with an on-chain guard (e.g., a `metadata_signed` flag that blocks `set_metadata` once set).

---

### Proof of Concept

```
1. Deploy OmniToken with decimals=18, name="Alpha", symbol="ALP".
2. Call bridge.log_metadata(token_id).
   → ft_metadata() returns {name="Alpha", symbol="ALP", decimals=18}
   → MPC signs MetadataPayload{token, name="Alpha", symbol="ALP", decimals=18}
   → Signed payload emitted as NEAR event. Attacker captures it.
3. DAO calls bridge.set_metadata(token_id, decimals=Some(6)).
   → OmniToken.set_metadata(decimals=Some(6)) succeeds (only controller check).
   → ft_metadata() now returns decimals=6.
4. Token is deployed on Chain A (correctly, via a fresh log_metadata call) with decimals=6.
5. Token has NOT yet been deployed on Chain B.
6. Attacker submits old signed payload (decimals=18) to Chain B's OmniBridge.deployToken().
   → Signature verifies (valid MPC sig, no nonce check).
   → !isBridgeToken[nearToEthToken[token]] == true (not yet deployed on B).
   → Token deployed on Chain B with decimals=18.
   → bridge stores token_decimals[chainB_token_address] = 18.
7. User transfers 1.0 token (1_000_000 units at decimals=6) from NEAR to Chain B.
   → normalize_amount(1_000_000, stored_decimals=18) → 1_000_000 / 10^(18-6) = 0 (rounds to zero).
   → User receives 0 tokens on Chain B. Funds are permanently lost.
```

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L329-366)
```rust
    #[private]
    #[result_serializer(borsh)]
    pub fn log_metadata_callback(
        &self,
        #[callback] metadata: FungibleTokenMetadata,
        token_id: &AccountId,
    ) -> Promise {
        require!(
            !metadata.name.is_empty() && !metadata.symbol.is_empty(),
            BridgeError::InvalidMetadata.as_ref()
        );

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

        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_LOG_METADATA_CALLBACK_GAS)
                    .sign_log_metadata_callback(metadata_payload),
            )
    }
```

**File:** near/omni-bridge/src/lib.rs (L471-480)
```rust
        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );
```

**File:** near/omni-token/src/lib.rs (L156-188)
```rust
    fn set_metadata(
        &mut self,
        name: Option<String>,
        symbol: Option<String>,
        reference: Option<String>,
        reference_hash: Option<Base64VecU8>,
        decimals: Option<u8>,
        icon: Option<String>,
    ) {
        self.assert_controller();

        let mut metadata = self.ft_metadata();
        if let Some(name) = name {
            metadata.name = name;
        }
        if let Some(symbol) = symbol {
            metadata.symbol = symbol;
        }
        if let Some(reference) = reference {
            metadata.reference = Some(reference);
        }
        if let Some(reference_hash) = reference_hash {
            metadata.reference_hash = Some(reference_hash);
        }
        if let Some(decimals) = decimals {
            metadata.decimals = decimals;
        }
        if let Some(icon) = icon {
            metadata.icon = Some(icon);
        }

        self.metadata.set(&metadata);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-195)
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
        uint8 decimals = _normalizeDecimals(metadata.decimals);

        // slither-disable-next-line reentrancy-no-eth
        address bridgeTokenProxy = address(
            new ERC1967Proxy(
                tokenImplementationAddress,
                abi.encodeWithSelector(
                    BridgeToken.initialize.selector,
                    metadata.name,
                    metadata.symbol,
                    decimals
                )
            )
        );

        deployTokenExtension(
            metadata.token,
            bridgeTokenProxy,
            decimals,
            metadata.decimals
        );

        emit BridgeTypes.DeployToken(
            bridgeTokenProxy,
            metadata.token,
            metadata.name,
            metadata.symbol,
            decimals,
            metadata.decimals
        );

        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);

        return bridgeTokenProxy;
    }
```

**File:** evm/SECURITY.md (L10-10)
```markdown
- **`deployToken` signature has no chain ID**: Metadata signatures are intentionally chain-agnostic — one NEAR-side signature deploys the same token on all EVM chains
```

**File:** starknet/src/omni_bridge.cairo (L202-209)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);

            let token_id_hash = compute_keccak_byte_array(@payload.token);
            let existing_token = self.near_to_starknet_token.read(token_id_hash);
            assert(existing_token.is_zero(), 'ERR_TOKEN_ALREADY_DEPLOYED');
```
