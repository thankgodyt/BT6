### Title
Unrestricted `log_metadata` Allows Any Caller to Obtain MPC-Signed Metadata for Arbitrary NEAR Accounts, Enabling Fake Bridge Token Deployment on EVM — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `log_metadata` function in the NEAR omni-bridge contract imposes no caller-identity restriction. Any unprivileged NEAR account can invoke it with an arbitrary `token_id`, causing the bridge to fetch metadata from that account and request an MPC signature over it. The resulting signed payload is a valid credential that can be submitted to any EVM `OmniBridge.deployToken()` to register a new bridge token. An attacker who controls a NEAR contract returning fabricated metadata (e.g., `name="USD Coin"`, `symbol="USDC"`) can therefore cause the MPC network to endorse and deploy a counterfeit bridge token on every supported EVM chain.

---

### Finding Description

`log_metadata` is decorated only with `#[pause(except(roles(Role::DAO)))]`. When the contract is in its normal (unpaused) operating state, the function is callable by **any** NEAR account with any `token_id` argument:

```rust
// near/omni-bridge/src/lib.rs  (lines 316-327)
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

The callback performs only a non-empty-string check before signing:

```rust
// near/omni-bridge/src/lib.rs  (lines 329-366)
pub fn log_metadata_callback(
    &self,
    #[callback] metadata: FungibleTokenMetadata,
    token_id: &AccountId,
) -> Promise {
    require!(
        !metadata.name.is_empty() && !metadata.symbol.is_empty(),
        BridgeError::InvalidMetadata.as_ref()
    );
    // builds MetadataPayload and calls MPC signer
    ...
}
```

There is no check that:
- the caller is a privileged role (DAO, MetadataManager, etc.),
- `token_id` is already registered in the bridge, or
- `token_id` is not a freshly deployed attacker-controlled contract.

The signed `LogMetadataEvent` is then consumed on EVM by `OmniBridge.deployToken()`, which verifies only the MPC signature and the absence of a prior token registration:

```solidity
// evm/src/omni-bridge/contracts/OmniBridge.sol  (lines 135-192)
function deployToken(
    bytes calldata signatureData,
    BridgeTypes.MetadataPayload calldata metadata
) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
    ...
    if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
        revert InvalidSignature();
    }
    require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST");
    ...
    isBridgeToken[address(bridgeTokenProxy)] = true;
    ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
    nearToEthToken[metadata.token] = address(bridgeTokenProxy);
    ...
}
```

Because the MPC signature is the sole trust anchor for `deployToken`, obtaining it for attacker-controlled metadata is sufficient to register a counterfeit token in the bridge's canonical mapping on every EVM chain.

---

### Impact Explanation

An attacker deploys a NEAR contract whose `ft_metadata()` returns fabricated values (e.g., `name = "USD Coin"`, `symbol = "USDC"`, `decimals = 6`). After calling `log_metadata` and collecting the MPC-signed payload, the attacker calls `deployToken` on each EVM `OmniBridge`. The result is:

1. A counterfeit ERC-20 token is registered in `nearToEthToken` / `ethToNearToken` as the canonical EVM representation of the attacker's NEAR account.
2. The token carries the bridge's MPC endorsement, making it indistinguishable from a legitimately deployed bridge token at the protocol level.
3. Any user who bridges assets to or from this fake token loses funds: tokens locked on the source chain are matched against a worthless ERC-20 on the destination chain.
4. Because `deployToken` is a one-time operation per `metadata.token` string, the attacker can also pre-empt the legitimate registration of a real NEAR token (e.g., `usdc.near`) if it has not yet been logged, permanently poisoning the bridge's token-address binding for that identifier.

This is a **token metadata binding confusion** issue that directly changes user balances (locked source-chain assets are matched to worthless destination-chain tokens).

---

### Likelihood Explanation

The attack requires only:
- Deploying a NEAR contract (permissionless, costs a few NEAR in storage),
- Calling `log_metadata` (permissionless when unpaused, costs MPC signing fee),
- Calling `deployToken` on EVM (permissionless, costs gas).

No privileged access, no leaked keys, no social engineering, and no validator collusion are needed. The entire attack is executable by any NEAR account holder.

---

### Recommendation

Restrict `log_metadata` to authorized callers. The simplest fix mirrors the pattern already used for `set_token_metadata`:

```rust
// Restrict to DAO or a dedicated MetadataManager role
#[access_control_any(roles(Role::DAO, Role::MetadataManager))]
#[pause(except(roles(Role::DAO)))]
pub fn log_metadata(&self, token_id: &AccountId) -> Promise { ... }
```

Alternatively, require that `token_id` is already registered as a known token in the bridge before signing its metadata.

---

### Proof of Concept

```
1. Attacker deploys a NEAR contract at `fake-usdc.attacker.near`.
   The contract's `ft_metadata()` returns:
     { name: "USD Coin", symbol: "USDC", decimals: 6 }

2. Attacker calls (permissionlessly, contract unpaused):
     omni_bridge.log_metadata({ token_id: "fake-usdc.attacker.near" })

3. Bridge fetches metadata from `fake-usdc.attacker.near`, constructs:
     MetadataPayload { token: "fake-usdc.attacker.near", name: "USD Coin",
                       symbol: "USDC", decimals: 6 }
   and requests an MPC signature over keccak256(borsh(payload)).

4. MPC returns a valid ECDSA signature. Bridge emits LogMetadataEvent
   containing the signature and payload.

5. Attacker submits the signature + payload to EVM OmniBridge.deployToken().
   Signature check passes (signed by nearBridgeDerivedAddress).
   "ERR_TOKEN_EXIST" check passes (no prior token for this id).
   A new ERC-20 "USD Coin (USDC)" is deployed and registered:
     nearToEthToken["fake-usdc.attacker.near"] = <fake ERC-20 address>

6. The fake ERC-20 is now the bridge's canonical EVM token for
   "fake-usdc.attacker.near". Any user bridging to this NEAR account
   receives worthless tokens; their source-chain assets are locked.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-194)
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
```
