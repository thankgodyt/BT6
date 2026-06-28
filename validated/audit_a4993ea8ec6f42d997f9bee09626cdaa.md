### Title
Unchecked Token Decimal Value Enables Permanent Freezing of Bridged Funds via Arithmetic Overflow - (`near/omni-bridge/src/lib.rs`)

### Summary

The NEAR bridge contract's `denormalize_amount` and `normalize_amount` functions perform unchecked u128 arithmetic that overflows when a token's `origin_decimals` minus its normalized `decimals` is ≥ 39. Because `log_metadata_callback` never validates the decimal value reported by a NEAR token, a malicious actor can register a token with extreme decimals (e.g., 57), causing every subsequent cross-chain transfer for that token to panic and permanently freeze user funds.

### Finding Description

The bridge normalizes token amounts between chains using two functions in `near/omni-bridge/src/lib.rs`:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // ← unchecked multiplication
}

fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))   // ← 10^diff_decimals itself overflows first
}
``` [1](#0-0) 

`u128::MAX ≈ 3.4 × 10^38`, so `10_u128.pow(39)` already overflows. With `decimals = 18` (the EVM cap), any token whose `origin_decimals ≥ 57` produces `diff_decimals ≥ 39` and triggers a panic on every call.

The `Decimals` pair `{ decimals, origin_decimals }` is written by `add_token`, which is called from `bind_token_callback` with values taken directly from the on-chain `DeployToken` event:

```rust
self.add_token(
    &deploy_token.token,
    &deploy_token.token_address,
    deploy_token.decimals,          // normalized (e.g. 18)
    deploy_token.origin_decimals,   // raw value from EVM event (e.g. 57)
);
``` [2](#0-1) 

The `origin_decimals` value in the EVM `DeployToken` event is set to `metadata.decimals` — the raw value from the MPC-signed `MetadataPayload`, which originates from `log_metadata_callback` on NEAR:

```rust
pub fn log_metadata_callback(
    &self,
    #[callback] metadata: FungibleTokenMetadata,
    token_id: &AccountId,
) -> Promise {
    require!(
        !metadata.name.is_empty() && !metadata.symbol.is_empty(),
        BridgeError::InvalidMetadata.as_ref()
    );
    // ← no validation of metadata.decimals
    let metadata_payload = MetadataPayload {
        ...
        decimals: metadata.decimals,   // any u8 value (0–255) is accepted
    };
``` [3](#0-2) 

The EVM side caps the deployed bridge token's own decimal field at 18 via `_normalizeDecimals`, but faithfully preserves the raw value as `originDecimals` in the `DeployToken` event:

```solidity
uint8 decimals = _normalizeDecimals(metadata.decimals);   // capped at 18
emit BridgeTypes.DeployToken(
    bridgeTokenProxy, metadata.token, metadata.name, metadata.symbol,
    decimals,           // 18
    metadata.decimals   // 57 — raw value preserved
);
``` [4](#0-3) 

### Impact Explanation

**EVM → NEAR direction (critical):** A user calls `initTransfer` on EVM, burning/locking their bridge tokens. The NEAR `fin_transfer_callback` then calls `denormalize_amount`, which panics due to overflow. Because the EVM tokens are already burned and the NEAR callback always panics, the funds are permanently frozen — there is no recovery path. [5](#0-4) 

**NEAR → EVM direction:** `sign_transfer` calls `normalize_amount`, which also panics (the `10_u128.pow(diff_decimals)` computation overflows before the division). The MPC signature is never produced, and the NEAR tokens locked in the bridge contract cannot be recovered. [6](#0-5) 

### Likelihood Explanation

The entire registration path is permissionless:

1. Deploy a NEAR NEP-141 token reporting `decimals = 57` in `ft_metadata()`.
2. Call `log_metadata` on NEAR (public, no access control) — MPC signs the payload with `decimals = 57` because `log_metadata_callback` only checks that `name` and `symbol` are non-empty.
3. Call `deployToken` on EVM with the MPC signature — permissionless per `evm/SECURITY.md`.
4. Call `bind_token` on NEAR with the resulting EVM proof — permissionless. [7](#0-6) 

After step 4, `Decimals { decimals: 18, origin_decimals: 57 }` is stored. Any user who subsequently bridges this token from EVM to NEAR loses their funds permanently. The attacker does not need any privileged role, leaked key, or off-chain collusion.

### Recommendation

**Short term:** Add a bounds check in `log_metadata_callback` rejecting any `metadata.decimals` value that would produce an unsafe `diff_decimals` (e.g., reject if `decimals > 36` when the normalized cap is 18, leaving a safe margin). Also add the same guard in `bind_token_callback` before calling `add_token`.

**Long term:** Replace the unchecked arithmetic in `normalize_amount` and `denormalize_amount` with checked or saturating operations (`checked_mul`, `checked_pow`) and propagate errors explicitly rather than panicking, so a malformed token registration cannot permanently brick a transfer path.

### Proof of Concept

1. Deploy NEAR token `bad.near` with `ft_metadata()` returning `decimals: 57`.
2. Call `omni_bridge.log_metadata({ token_id: "bad.near" })` — succeeds, MPC signs `MetadataPayload { decimals: 57 }`.
3. Call `OmniBridge.deployToken(signature, { token: "bad.near", decimals: 57, ... })` on EVM — deploys `BridgeToken` with `decimals=18`, emits `DeployToken(..., decimals=18, originDecimals=57)`.
4. Call `omni_bridge.bind_token(...)` on NEAR with the EVM proof — stores `Decimals { decimals: 18, origin_decimals: 57 }`.
5. User acquires EVM bridge tokens and calls `initTransfer` — tokens burned on EVM.
6. Relayer submits proof to NEAR `fin_transfer` → `fin_transfer_callback` executes `denormalize_amount(amount, Decimals { decimals: 18, origin_decimals: 57 })` → `10_u128.pow(39)` overflows → NEAR transaction panics → transfer permanently unfinalisable → user funds lost. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** near/omni-bridge/src/lib.rs (L331-347)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L471-485)
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

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L720-726)
```rust
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
```

**File:** near/omni-bridge/src/lib.rs (L1241-1267)
```rust
    #[private]
    pub fn bind_token_callback(
        &mut self,
        attached_deposit: NearToken,
        #[callback_result]
        #[serializer(borsh)]
        call_result: Result<ProverResult, PromiseError>,
    ) -> NearToken {
        let Ok(ProverResult::DeployToken(deploy_token)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str());
        };

        require!(
            self.factories
                .get(&deploy_token.emitter_address.get_chain())
                == Some(deploy_token.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let storage_usage = env::storage_usage();

        self.add_token(
            &deploy_token.token,
            &deploy_token.token_address,
            deploy_token.decimals,
            deploy_token.origin_decimals,
        );
```

**File:** near/omni-bridge/src/lib.rs (L2776-2787)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }

    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L159-188)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L586-592)
```text
    function _normalizeDecimals(uint8 decimals) internal pure returns (uint8) {
        uint8 maxAllowedDecimals = 18;
        if (decimals > maxAllowedDecimals) {
            return maxAllowedDecimals;
        }
        return decimals;
    }
```
