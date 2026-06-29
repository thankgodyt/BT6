### Title
Unvalidated Cross-Contract Call in `log_metadata` Enables Attacker-Controlled Metadata Signing — (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `log_metadata` function on the NEAR bridge contract accepts any caller-supplied NEAR `AccountId` and makes an unconditional cross-contract call to `ft_metadata()` on that account. The returned metadata — including the `decimals` field — is fed directly into a `MetadataPayload` that the MPC signer signs. An attacker who deploys a malicious NEAR contract can obtain a valid MPC-signed metadata payload with attacker-controlled `decimals`, then use it to deploy a bridge token on every supported foreign chain (EVM, Starknet, Solana) with a fabricated decimal count. The stored `origin_decimals` value subsequently drives `normalize_amount` / `denormalize_amount` in `sign_transfer`, causing systematic mis-accounting of bridged amounts for that token.

### Finding Description

`log_metadata` is decorated only with `#[pause(except(roles(Role::DAO)))]`, meaning any unprivileged caller may invoke it when the contract is unpaused. [1](#0-0) 

The function makes a cross-contract call to `ft_metadata()` on the caller-supplied `token_id` with no check that the account is a registered token, a deployed bridge token, or even a legitimate NEP-141 contract. [2](#0-1) 

The callback constructs a `MetadataPayload` verbatim from the response and submits it to the MPC signer: [3](#0-2) 

The `MetadataPayload` type carries `token`, `name`, `symbol`, and `decimals` — all attacker-controlled: [4](#0-3) 

The resulting MPC signature is emitted as a `LogMetadataEvent` and is immediately usable on EVM `deployToken`: [5](#0-4) 

EVM `deployToken` emits a `DeployToken` event carrying both `decimals` (EVM-normalised) and `origin_decimals` (raw from the payload): [6](#0-5) 

NEAR `bind_token_callback` then stores both values into `token_decimals`: [7](#0-6) 

The stored `Decimals` struct drives all subsequent amount normalisation in `sign_transfer`: [8](#0-7) [9](#0-8) 

### Impact Explanation

By setting `origin_decimals` to a value that diverges from the actual NEAR token's decimal count, the attacker causes `normalize_amount` to apply the wrong scaling factor for every transfer of that token. Concretely:

- If `origin_decimals` is set **lower** than the real NEAR token decimals (e.g., `0` instead of `24`), the normalisation divides by a smaller power of ten, inflating the amount credited on the foreign chain relative to what was locked on NEAR.
- If `origin_decimals` is set **higher**, the normalisation deflates the amount, causing permanent loss for users who bridge that token.

Because the attacker controls the NEAR-side token contract, they can mint arbitrary amounts and exploit the inflated normalisation to receive disproportionately large quantities of the EVM bridge token. The EVM bridge token is a standard mintable/burnable asset accepted by the bridge's `finTransfer` path, so the inflated balance is redeemable within the bridge's own accounting. This constitutes balance manipulation and escrow mis-accounting within the bridge protocol.

The same signed payload is accepted by Starknet `deploy_token` and Solana `deploy_token`, both of which verify the MPC signature and store the attacker-supplied decimals: [10](#0-9) [11](#0-10) 

### Likelihood Explanation

`log_metadata` is a public, permissionless function (gated only by the global pause flag). Deploying a malicious NEAR contract that returns crafted `ft_metadata()` output requires no special privilege — any NEAR account holder can do it. The full attack chain (deploy malicious contract → call `log_metadata` → submit signed payload to EVM/Starknet/Solana `deployToken` → call NEAR `bind_token`) is executable by a single unprivileged actor with no off-chain coordination.

### Recommendation

1. **Validate `token_id` before calling `ft_metadata`**: Require that the supplied `token_id` is already registered in `token_address_to_id` or `deployed_tokens` before making the cross-contract call. This restricts `log_metadata` to tokens the bridge already knows about.
2. **Alternatively, restrict callers**: Gate `log_metadata` behind a role (e.g., `Role::MetadataManager` or `Role::DAO`) so only trusted parties can trigger MPC signing of metadata.
3. **Validate `decimals` range**: Enforce that the `decimals` value returned by `ft_metadata` falls within an expected range (e.g., 1–24) before signing.

### Proof of Concept

1. Attacker deploys `evil.near` implementing `ft_metadata()` returning `{ name: "Evil", symbol: "EVL", decimals: 0 }`.
2. Attacker calls `log_metadata("evil.near")` on the NEAR bridge (no access control when unpaused).
3. Bridge calls `evil.near::ft_metadata()`, receives `decimals: 0`.
4. Bridge constructs `MetadataPayload { token: "evil.near", name: "Evil", symbol: "EVL", decimals: 0 }` and requests MPC signature.
5. MPC signs; `LogMetadataEvent` is emitted with the signature.
6. Attacker submits `deployToken(signature, { token: "evil.near", decimals: 0 })` to EVM `OmniBridge`.
7. EVM deploys bridge token with 0 decimals; emits `DeployToken { origin_decimals: 0, decimals: 0 }`.
8. Attacker calls NEAR `bind_token` with proof of the EVM event; NEAR stores `token_decimals = { decimals: 0, origin_decimals: 0 }`.
9. Attacker mints tokens on `evil.near` (they control the contract) and initiates a transfer via `ft_transfer_call` to the bridge.
10. `sign_transfer` calls `normalize_amount(amount, { decimals: 0, origin_decimals: 0 })` — the stored `origin_decimals: 0` diverges from the actual 24-decimal NEAR token, producing a mis-scaled amount on the EVM side.
11. The signed transfer payload is submitted to EVM `finTransfer`, minting an inflated quantity of the bridge token to the attacker. [1](#0-0) [12](#0-11) [9](#0-8)

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

**File:** near/omni-bridge/src/lib.rs (L1262-1267)
```rust
        self.add_token(
            &deploy_token.token,
            &deploy_token.token_address,
            deploy_token.decimals,
            deploy_token.origin_decimals,
        );
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-153)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L181-188)
```text
        emit BridgeTypes.DeployToken(
            bridgeTokenProxy,
            metadata.token,
            metadata.name,
            metadata.symbol,
            decimals,
            metadata.decimals
        );
```

**File:** near/omni-bridge/src/storage.rs (L132-136)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```

**File:** starknet/src/omni_bridge.cairo (L202-211)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);

            let token_id_hash = compute_keccak_byte_array(@payload.token);
            let existing_token = self.near_to_starknet_token.read(token_id_hash);
            assert(existing_token.is_zero(), 'ERR_TOKEN_ALREADY_DEPLOYED');

            let decimals = _normalizeDecimals(payload.decimals);
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L66-76)
```rust
    pub fn deploy_token(
        ctx: Context<DeployToken>,
        data: SignedPayload<DeployTokenPayload>,
    ) -> Result<()> {
        msg!("Deploying token");

        data.verify_signature((), &ctx.accounts.common.config.derived_near_bridge_address)?;
        ctx.accounts.initialize_token_metadata(data.payload)?;

        Ok(())
    }
```
