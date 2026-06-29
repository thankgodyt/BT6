### Title
`origin_decimals` Ignored in `deploy_token_internal`, Causing Incorrect Amount Normalization for High-Decimal Tokens - (File: `near/omni-bridge/src/lib.rs`)

### Summary

`deploy_token_internal` always stores `origin_decimals = decimals` (the destination-chain-clamped value) in the `token_decimals` map, discarding the true `origin_decimals` carried in the `DeployTokenMessage`. For any NEAR-origin token whose decimal count exceeds the destination chain's cap (18 for EVM/Starknet, 9 for Solana), every subsequent `normalize_amount` and `denormalize_amount` call uses a zero-difference exponent, producing amounts that are off by a factor of `10^(origin_decimals − clamped_decimals)`.

### Finding Description

**Root cause — `deploy_token_internal` discards `origin_decimals`**

`deploy_token_internal` receives a `BasicMetadata` that only carries the clamped `decimals` field, then passes it twice to `add_token`:

```rust
// near/omni-bridge/src/lib.rs:2414-2418
self.add_token(
    &token_id,
    token_address,
    metadata.decimals,   // clamped (e.g. 18)
    metadata.decimals,   // BUG: should be origin_decimals (e.g. 24)
);
``` [1](#0-0) 

`add_token` stores the pair as `Decimals { decimals, origin_decimals }`:

```rust
// near/omni-bridge/src/lib.rs:2724-2735
self.token_decimals.insert(
    token_address,
    &Decimals { decimals, origin_decimals },
)
``` [2](#0-1) 

Because both fields are set to the clamped value, the stored `Decimals` struct always has `origin_decimals == decimals`, making `diff_decimals = 0` in every normalization call.

**Where `origin_decimals` is available but ignored**

The EVM Wormhole extension emits both fields:

```solidity
// evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol:54-61
bytes1(decimals),        // clamped (18)
bytes1(originDecimals)   // original (e.g. 24)
``` [3](#0-2) 

The Starknet `DeployToken` event also emits both:

```cairo
// starknet/src/omni_bridge.cairo:235-236
decimals,
origin_decimals: payload.decimals,
``` [4](#0-3) 

The NEAR prover parses both into `DeployTokenMessage { decimals, origin_decimals, … }`:

```rust
// near/omni-types/src/starknet/events.rs:161-162
let decimals: u8 = cursor.read_u64()?.try_into().map_err(stringify)?;
let origin_decimals: u8 = cursor.read_u64()?.try_into().map_err(stringify)?;
``` [5](#0-4) 

Yet `deploy_token_callback` silently drops `origin_decimals` when constructing `BasicMetadata`:

```rust
// near/omni-bridge/src/lib.rs:1165-1174
self.deploy_token_internal(
    chain,
    &metadata.token_address,
    BasicMetadata {
        name: metadata.name,
        symbol: metadata.symbol,
        decimals: metadata.decimals,   // clamped only; origin_decimals lost
    },
    attached_deposit,
)
``` [6](#0-5) 

**Downstream normalization functions**

```rust
// near/omni-bridge/src/lib.rs:2784-2786
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))   // always divides by 1 due to bug
}
``` [7](#0-6) 

```rust
// near/omni-bridge/src/lib.rs:2776-2778
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // always multiplies by 1 due to bug
}
``` [8](#0-7) 

**Decimal caps that trigger the bug**

- EVM / Starknet: `_normalizeDecimals` caps at 18. [9](#0-8) 
- Solana: `MAX_ALLOWED_DECIMALS = 9`. [10](#0-9) 

Any NEAR-origin token with more decimals than the cap (e.g., NEAR native = 24 decimals) triggers the bug.

### Impact Explanation

**NEAR → EVM (sign_transfer path)**

`sign_transfer` looks up the EVM token address and calls `normalize_amount`:

```rust
// near/omni-bridge/src/lib.rs:471-480
let decimals = self.token_decimals.get(&token_address)...;
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee()...,
    decimals,
);
``` [11](#0-10) 

With the bug, `normalize_amount(1e24, Decimals{18,18})` = `1e24` instead of the correct `1e18`. The MPC signature covers `1e24`. The EVM `finTransfer` mints `1e24` EVM tokens (= **1,000,000 EVM tokens** for 1 NEAR token). An attacker deposits 1 NEAR token and withdraws 1,000,000 EVM tokens — draining the EVM bridge.

**EVM → NEAR (fin_transfer_callback path)**

```rust
// near/omni-bridge/src/lib.rs:725
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
``` [12](#0-11) 

`denormalize_amount(1e18, Decimals{18,18})` = `1e18` instead of `1e24`. The user sent 1 EVM token but receives only `1e18` units of the 24-decimal NEAR token (= **0.000001 NEAR**). The remaining `999,999/1,000,000` of the value is permanently locked in the bridge.

### Likelihood Explanation

The attack path is fully permissionless:
1. Any user calls `log_metadata` on NEAR for a token with >18 decimals (e.g., NEAR native).
2. The EVM bridge deploys the capped token and emits `DeployToken`.
3. Any user calls `deploy_token` on NEAR with the Wormhole VAA proof — this is a public, unguarded function.
4. The incorrect `Decimals` entry is now stored.
5. Any user can exploit the inflated `sign_transfer` path or suffer the deflated `fin_transfer` path.

No admin compromise, no key leak, and no threshold-MPC collusion is required.

### Recommendation

1. Add `origin_decimals: u8` to `BasicMetadata` (or pass it as a separate parameter to `deploy_token_internal`).
2. In `deploy_token_callback`, populate it from `metadata.origin_decimals`.
3. In `deploy_token_internal`, call `add_token` with the correct `origin_decimals`:

```rust
self.add_token(
    &token_id,
    token_address,
    metadata.decimals,          // clamped destination decimals
    metadata.origin_decimals,   // true source decimals
);
```

4. Apply the same fix to `add_deployed_tokens` and `deploy_native_token` where applicable.

### Proof of Concept

**Setup**: NEAR native token (

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L725-725)
```rust
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
```

**File:** near/omni-bridge/src/lib.rs (L1165-1174)
```rust
        self.deploy_token_internal(
            chain,
            &metadata.token_address,
            BasicMetadata {
                name: metadata.name,
                symbol: metadata.symbol,
                decimals: metadata.decimals,
            },
            attached_deposit,
        )
```

**File:** near/omni-bridge/src/lib.rs (L2414-2419)
```rust
        self.add_token(
            &token_id,
            token_address,
            metadata.decimals,
            metadata.decimals,
        );
```

**File:** near/omni-bridge/src/lib.rs (L2724-2735)
```rust
        require!(
            self.token_decimals
                .insert(
                    token_address,
                    &Decimals {
                        decimals,
                        origin_decimals,
                    }
                )
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L54-61)
```text
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.DeployToken)),
            Borsh.encodeString(token),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            bytes1(decimals),
            bytes1(originDecimals)
        );
```

**File:** starknet/src/omni_bridge.cairo (L227-240)
```text
            self
                .emit(
                    Event::DeployToken(
                        DeployToken {
                            token_address: contract_address,
                            near_token_id: payload.token,
                            name: payload.name,
                            symbol: payload.symbol,
                            decimals,
                            origin_decimals: payload.decimals,
                        },
                    ),
                )
        }
```

**File:** near/omni-types/src/starknet/events.rs (L161-162)
```rust
    let decimals: u8 = cursor.read_u64()?.try_into().map_err(stringify)?;
    let origin_decimals: u8 = cursor.read_u64()?.try_into().map_err(stringify)?;
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

**File:** solana/programs/bridge_token_factory/src/constants.rs (L33-33)
```rust
pub const MAX_ALLOWED_DECIMALS: u8 = 9;
```
