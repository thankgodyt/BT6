### Title
Unvalidated Token Address in `log_metadata` Allows Arbitrary Cross-Contract Call with Bridge as Predecessor, Enabling Forged MPC-Signed Metadata Events - (File: near/omni-bridge/src/lib.rs)

### Summary
The publicly callable `log_metadata` function accepts an arbitrary `token_id` account and calls `ft_metadata()` on it without verifying the address is a registered bridge token. The asset-bearing `omni-bridge` contract becomes the `predecessor_account_id` in that call. The callback then forwards the attacker-controlled metadata directly to the MPC signer, producing a valid `LogMetadataEvent` signature for a fake token. This signed event can be submitted to foreign-chain bridge contracts to deploy a fraudulent bridged token with a valid protocol signature.

### Finding Description

`log_metadata` is a public, pause-gated (not role-gated) function:

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
``` [1](#0-0) 

Any unprivileged user can supply an arbitrary NEAR account ID as `token_id`. There is no check that the account is a registered or deployed bridge token (compare with `set_token_metadata`, which guards with `require!(self.is_deployed_token(&token))`). [2](#0-1) 

The callback receives the metadata returned by the attacker-controlled contract and immediately constructs a `MetadataPayload` using the attacker-supplied `token_id` and the forged `name`, `symbol`, and `decimals`, then calls the MPC signer:

```rust
pub fn log_metadata_callback(
    &self,
    #[callback] metadata: FungibleTokenMetadata,
    token_id: &AccountId,
) -> Promise {
    ...
    let metadata_payload = MetadataPayload {
        prefix: PayloadType::Metadata,
        token: token_id.to_string(),   // attacker-controlled
        name: metadata.name,           // attacker-controlled
        symbol: metadata.symbol,       // attacker-controlled
        decimals: metadata.decimals,   // attacker-controlled
    };
    ...
    ext_signer::ext(self.mpc_signer.clone())
        ...
        .sign(SignRequest { payload, ... })
``` [3](#0-2) 

On success, a `LogMetadataEvent` carrying a valid MPC signature over the forged payload is emitted: [4](#0-3) 

### Impact Explanation

A valid MPC-signed `LogMetadataEvent` is the exact input consumed by foreign-chain bridge contracts (EVM, Starknet, Solana) to deploy a new bridged token. An attacker who obtains such a signature for a fabricated token can:

1. Deploy a fraudulent bridge token on any supported foreign chain that carries a valid protocol signature — indistinguishable from a legitimately registered token at the protocol level.
2. Manipulate the token registry on foreign chains, potentially shadowing or colliding with legitimate token entries.
3. Lure users into bridging assets to the fake token, resulting in permanent loss of bridged funds.

This matches the **Critical** impact class: unauthorized minting / token metadata binding confusion enabling loss of bridged funds and authorization bypass of the token-deployment gate.

### Likelihood Explanation

`log_metadata` is callable by any NEAR account when the bridge is not paused. The attacker only needs to deploy a NEAR contract that implements `ft_metadata()` returning arbitrary values — a trivial task. No privileged access, leaked keys, or collusion is required. The attack is fully self-contained and repeatable.

### Recommendation

Before calling `ft_metadata()`, verify that `token_id` is a registered bridge token, mirroring the guard already present in `set_token_metadata`:

```rust
pub fn log_metadata(&self, token_id: &AccountId) -> Promise {
    require!(
        self.is_deployed_token(token_id)
            || self.token_address_to_id.values().any(|id| &id == token_id),
        "token_id is not a registered bridge token"
    );
    ext_token::ext(token_id.clone())
        ...
}
```

Alternatively, restrict `log_metadata` to DAO/MetadataManager roles, consistent with `set_token_metadata`.

### Proof of Concept

1. Attacker deploys `evil.near` implementing `ft_metadata()` that returns `{ name: "Fake USDC", symbol: "USDC", decimals: 6 }`.
2. Attacker calls `omni-bridge.near::log_metadata("evil.near")` with sufficient attached NEAR for MPC gas.
3. Bridge calls `evil.near::ft_metadata()` — `predecessor_account_id` inside `evil.near` is `omni-bridge.near`.
4. `evil.near` returns the forged metadata; `log_metadata_callback` constructs `MetadataPayload { token: "evil.near", name: "Fake USDC", symbol: "USDC", decimals: 6 }`.
5. MPC signer signs the payload; `LogMetadataEvent` with a valid signature is emitted on-chain.
6. Attacker submits the signed event to the EVM bridge's `deployToken` function; a new `BridgeToken` named "Fake USDC" is deployed by the legitimate bridge factory with a valid protocol signature.
7. Users bridging to this token lose funds permanently.

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

**File:** near/omni-bridge/src/lib.rs (L1573-1584)
```rust
    #[access_control_any(roles(Role::DAO, Role::MetadataManager))]
    pub fn set_token_metadata(
        &mut self,
        address: OmniAddress,
        name: Option<String>,
        symbol: Option<String>,
        icon: Option<String>,
        reference: Option<String>,
        reference_hash: Option<Base64VecU8>,
    ) -> Promise {
        let token = self.get_token_id(&address);
        require!(self.is_deployed_token(&token));
```
