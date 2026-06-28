### Title
Unvalidated `token_id` in `log_metadata` Allows Any Caller to Obtain MPC-Signed Metadata for Arbitrary NEAR Contracts, Enabling Fake Bridge Token Deployment on Foreign Chains - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`log_metadata` is a publicly callable function (no access control beyond the global pause) that accepts an arbitrary `token_id` NEAR account without checking whether it is a registered bridge token. The bridge then calls `ft_metadata()` on that arbitrary account, and if the call succeeds, signs the returned metadata with the bridge's MPC key and emits a `LogMetadataEvent`. Because the MPC signature is what grants legitimacy to a token registration on foreign chains, an attacker can obtain a valid bridge-signed metadata event for any NEAR account they control, and use it to deploy a fraudulent bridge token on EVM (or other foreign chains).

---

### Finding Description

In `near/omni-bridge/src/lib.rs`, the `log_metadata` function is:

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

There is no check that `token_id` is a registered bridge token (e.g., `self.is_deployed_token(token_id)`, or a lookup in `token_address_to_id` / `token_id_to_address`). The only access control is the `#[pause]` macro, which is bypassed when the contract is not paused.

The callback `log_metadata_callback` performs only a trivial non-emptiness check on the returned metadata:

```rust
require!(
    !metadata.name.is_empty() && !metadata.symbol.is_empty(),
    BridgeError::InvalidMetadata.as_ref()
);
``` [2](#0-1) 

After this check, the callback constructs a `MetadataPayload` from the attacker-controlled metadata and submits it to the MPC signer for signing:

```rust
ext_signer::ext(self.mpc_signer.clone())
    .with_static_gas(MPC_SIGNING_GAS)
    .with_attached_deposit(env::attached_deposit())
    .sign(SignRequest {
        payload,
        path: SIGN_PATH.to_owned(),
        key_version: 0,
    })
``` [3](#0-2) 

The resulting `SignTransferEvent` / `LogMetadataEvent` carries a valid MPC signature over attacker-chosen token name, symbol, and decimals, bound to an attacker-chosen NEAR account ID.

By contrast, the `add_prover` and `add_factory` admin functions are correctly gated behind `Role::DAO`:

```rust
#[access_control_any(roles(Role::DAO))]
pub fn add_prover(&mut self, chain: ChainKind, account_id: AccountId) {
    self.provers.insert(&chain, &account_id);
}
``` [4](#0-3) 

No equivalent allowlist guard exists for `log_metadata`.

---

### Impact Explanation

The MPC-signed `LogMetadataEvent` is the authoritative proof used by foreign-chain bridge contracts (EVM, Solana, Starknet) to deploy a new bridge token and bind it to a NEAR account. An attacker who obtains a valid MPC signature over fake metadata can:

1. Deploy a fraudulent bridge token on EVM (or another foreign chain) that is indistinguishable from a legitimate bridge token at the signature-verification level.
2. Bind this fraudulent EVM token to an attacker-controlled NEAR account, creating a false token-address mapping in the bridge ecosystem.
3. Cause token metadata binding confusion: users or integrators who rely on the bridge's signed metadata to identify legitimate tokens will be misled into interacting with the fraudulent token.
4. If the fraudulent token is made to mimic a high-value token (e.g., same name/symbol/decimals as USDC), users who bridge assets to the fraudulent EVM token will receive worthless tokens while their real NEAR-side assets are consumed.

This satisfies the **Critical** impact category: *token metadata binding confusion that changes user or protocol balances*, and *unauthorized transaction / authorization bypass that lets an attacker execute bridge actions* (deploying a bridge token without going through the legitimate proof-based `deploy_token` path).

---

### Likelihood Explanation

- `log_metadata` is callable by any NEAR account with no role requirement, only the global pause gate.
- Deploying a NEAR contract that implements `ft_metadata()` returning arbitrary data costs a trivial amount of NEAR.
- The attacker only needs to attach enough NEAR to cover MPC signing gas.
- No privileged access, leaked keys, or validator collusion is required.
- The attack is fully self-contained on-chain.

Likelihood is **High**.

---

### Recommendation

Add a validation check at the start of `log_metadata` to ensure `token_id` is a token already registered in the bridge's token registry before proceeding to call `ft_metadata()` and sign the result:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn log_metadata(&self, token_id: &AccountId) -> Promise {
    // Ensure only registered bridge tokens can have their metadata signed
    require!(
        self.token_address_to_id.values().any(|id| &id == token_id)
            || self.is_deployed_token(token_id),
        BridgeError::TokenNotRegistered.as_ref()
    );
    ext_token::ext(token_id.clone())
        ...
}
```

Alternatively, maintain an explicit allowlist of `token_id`s that are permitted to have their metadata logged, managed by `Role::DAO`, analogous to how `add_prover` and `add_factory` are gated.

---

### Proof of Concept

1. Attacker deploys a NEAR contract `fake-usdc.attacker.near` implementing `ft_metadata()` that returns `{name: "USD Coin", symbol: "USDC", decimals: 6}`.
2. Attacker calls `log_metadata("fake-usdc.attacker.near")` on the bridge, attaching sufficient NEAR for MPC gas.
3. Bridge calls `ft_metadata()` on `fake-usdc.attacker.near`; the malicious contract returns the fake metadata.
4. `log_metadata_callback` passes the trivial non-emptiness check and constructs:
   ```
   MetadataPayload { token: "fake-usdc.attacker.near", name: "USD Coin", symbol: "USDC", decimals: 6 }
   ``` [5](#0-4) 
5. The bridge submits this payload to `self.mpc_signer` and receives a valid MPC signature.
6. A `LogMetadataEvent` is emitted containing the valid MPC signature over the fake metadata.
7. Attacker submits this signed event to the EVM bridge contract's `deployToken` function. The EVM bridge verifies the MPC signature (which is valid), and deploys a new ERC-20 bridge token named "USD Coin" (USDC) backed by `fake-usdc.attacker.near`.
8. Users who bridge assets to this fraudulent EVM token receive worthless tokens; their NEAR-side assets are consumed by the bridge.

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

**File:** near/omni-bridge/src/lib.rs (L336-339)
```rust
        require!(
            !metadata.name.is_empty() && !metadata.symbol.is_empty(),
            BridgeError::InvalidMetadata.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L341-347)
```rust
        let metadata_payload = MetadataPayload {
            prefix: PayloadType::Metadata,
            token: token_id.to_string(),
            name: metadata.name,
            symbol: metadata.symbol,
            decimals: metadata.decimals,
        };
```

**File:** near/omni-bridge/src/lib.rs (L353-362)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L1749-1752)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn add_prover(&mut self, chain: ChainKind, account_id: AccountId) {
        self.provers.insert(&chain, &account_id);
    }
```
