### Title
Permissionless `log_metadata` Accepts Arbitrary NEAR Account IDs, Enabling MPC Signing of Attacker-Controlled Token Metadata — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary
The NEAR bridge contract's `log_metadata` function is callable by any unprivileged user and makes a cross-contract call to `ft_metadata()` on an arbitrary, attacker-supplied NEAR account ID. The returned name, symbol, and decimals are used without meaningful validation to construct a `MetadataPayload` that is submitted to the MPC signer for signing. An attacker who deploys a malicious NEAR contract can obtain a valid MPC-signed metadata payload for any name/symbol combination, enabling deployment of counterfeit bridge tokens on EVM and Starknet.

---

### Finding Description

`log_metadata` is a public function gated only by a pause flag (not by any role or allowlist): [1](#0-0) 

It calls `ft_metadata()` on the caller-supplied `token_id` — any valid NEAR account ID — and passes the result to `log_metadata_callback`: [2](#0-1) 

The only validation applied to the returned metadata is that `name` and `symbol` are non-empty: [3](#0-2) 

The unvalidated `metadata.name`, `metadata.symbol`, and `metadata.decimals` are then packed into a `MetadataPayload` and sent directly to the MPC signer: [4](#0-3) 

The resulting MPC signature is emitted as a `LogMetadataEvent`: [5](#0-4) 

On the EVM side, `deployToken` accepts this MPC-signed `MetadataPayload` and deploys a new `BridgeToken` contract initialized with the attacker-controlled `name`, `symbol`, and `decimals`: [6](#0-5) 

On Starknet, `deploy_token` similarly accepts the signed payload and deploys a new bridge token contract with the attacker-controlled metadata: [7](#0-6) 

The `MetadataPayload` type confirms that `name`, `symbol`, and `decimals` are free-form strings with no protocol-level constraints: [8](#0-7) 

---

### Impact Explanation

An attacker deploys a malicious NEAR contract at any account ID (e.g., `fake-usdc.near`) whose `ft_metadata()` returns `name: "USD Coin"`, `symbol: "USDC"`, `decimals: 6`. After calling `log_metadata("fake-usdc.near")`, the bridge obtains an MPC-signed payload for this metadata. The attacker then calls `deployToken` on EVM or Starknet, deploying a bridge token named "USD Coin" / "USDC" that is canonically mapped to `fake-usdc.near`. Since the attacker controls `fake-usdc.near`, they can mint unlimited tokens on the NEAR side and bridge them to EVM/Starknet as this counterfeit "USDC" bridge token. Any liquidity pool, protocol, or user that accepts this token by name/symbol rather than by verified contract address is exposed to balance manipulation. This is a **token metadata binding confusion** attack: the bridge's MPC signing authority is abused to certify attacker-chosen metadata as legitimate, creating counterfeit bridge tokens indistinguishable by name/symbol from real ones.

---

### Likelihood Explanation

The attack requires only: (1) deploying a NEAR contract (trivial, costs a small NEAR deposit), and (2) calling the public `log_metadata` function. No special role, key, or permission is needed. The MPC signing happens automatically as part of the bridge's normal flow. The barrier to execution is extremely low. Counterfeit token deployment on EVM/Starknet is equally permissionless. The primary constraint is that users must be deceived into interacting with the counterfeit token, but token impersonation attacks are a well-established and frequently exploited attack vector in DeFi.

---

### Recommendation

1. **Allowlist approach**: Maintain a registry of approved NEAR token account IDs that are permitted to be logged via `log_metadata`. Reject calls for accounts not in the registry.
2. **Access control**: Gate `log_metadata` behind a role (e.g., `Role::DAO` or a dedicated `TokenRegistrar` role) so that only trusted parties can initiate MPC signing of metadata payloads.
3. **Metadata validation**: At minimum, validate that the `token_id` passed to `log_metadata` is a known, previously registered token in the bridge's internal state before proceeding with MPC signing.

---

### Proof of Concept

1. Attacker deploys `fake-usdc.near` — a NEAR contract implementing `ft_metadata()` that returns `{spec: "ft-1.0.0", name: "USD Coin", symbol: "USDC", decimals: 6, icon: null, reference: null, reference_hash: null}`.
2. Attacker calls `log_metadata("fake-usdc.near")` on the NEAR bridge contract (public, no role required).
3. Bridge executes `ext_token::ext("fake-usdc.near").ft_metadata()` → receives attacker-controlled metadata.
4. `log_metadata_callback` passes the non-empty name/symbol check and constructs `MetadataPayload {prefix: Metadata, token: "fake-usdc.near", name: "USD Coin", symbol: "USDC", decimals: 6}`.
5. Bridge calls `mpc_signer.sign(keccak256(borsh(payload)))` → MPC signs the payload.
6. `sign_log_metadata_callback` emits a `LogMetadataEvent` containing the MPC signature and the metadata payload.
7. Attacker submits the signature and payload to `OmniBridge.deployToken()` on Ethereum → a new `BridgeToken` proxy is deployed with `name = "USD Coin"`, `symbol = "USDC"`, `decimals = 6`, mapped to `"fake-usdc.near"`.
8. Attacker mints arbitrary amounts of tokens on `fake-usdc.near` and bridges them to Ethereum as counterfeit USDC, targeting any protocol or user that resolves tokens by name/symbol.

### Citations

**File:** near/omni-bridge/src/lib.rs (L316-327)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn log_metadata(&self, token_id: &AccountId) -> Promise {
        ext_token::ext(token_id.clone())
            .with_static_gas(LOG_METADATA_GAS)
            .ft_metadata()
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(LOG_METADATA_CALLBACK_GAS)
                    .with_attached_deposit(env::attached_deposit())
                    .log_metadata_callback(token_id),
            )
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

**File:** near/omni-bridge/src/lib.rs (L370-384)
```rust
    pub fn sign_log_metadata_callback(
        &self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] metadata_payload: MetadataPayload,
    ) {
        if let Ok(signature) = call_result {
            env::log_str(
                &OmniBridgeEvent::LogMetadataEvent {
                    signature,
                    metadata_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-172)
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
```

**File:** starknet/src/omni_bridge.cairo (L202-225)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);

            let token_id_hash = compute_keccak_byte_array(@payload.token);
            let existing_token = self.near_to_starknet_token.read(token_id_hash);
            assert(existing_token.is_zero(), 'ERR_TOKEN_ALREADY_DEPLOYED');

            let decimals = _normalizeDecimals(payload.decimals);

            let mut constructor_calldata: Array<felt252> = array![];
            (payload.name.clone(), payload.symbol.clone(), decimals)
                .serialize(ref constructor_calldata);

            // Use the low part of the u256 hash to ensure it fits in felt252
            let salt: felt252 = token_id_hash.low.into();
            let (contract_address, _) = deploy_syscall(
                self.bridge_token_class_hash.read(), salt, constructor_calldata.span(), false,
            )
                .unwrap_syscall();

            self.starknet_to_near_token.write(contract_address, payload.token.clone());
            self.near_to_starknet_token.write(token_id_hash, contract_address);
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
