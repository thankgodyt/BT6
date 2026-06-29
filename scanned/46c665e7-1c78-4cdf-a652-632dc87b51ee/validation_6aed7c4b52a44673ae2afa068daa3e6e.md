### Title
Stale Token Decimals Stored via Unrestricted `logMetadata` Enable Decimal Normalization Abuse — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `logMetadata` function in `OmniBridge.sol` reads `decimals()` from an arbitrary ERC20 token at call time and emits an event that causes the NEAR bridge to permanently store those decimals in `token_decimals: LookupMap<OmniAddress, Decimals>`. Because `logMetadata` has no access control and can be called by anyone for any token address, an attacker controlling a token whose `decimals()` return value can change (e.g., a malicious upgradeable proxy) can cause the NEAR bridge to store a deliberately wrong decimal value. All subsequent cross-chain transfers for that token are then normalized using the stale/wrong decimal, enabling over-minting of bridged tokens on NEAR.

---

### Finding Description

`OmniBridge.logMetadata` is a public, payable function with no role restriction:

```solidity
function logMetadata(address tokenAddress) external payable {
    string memory name  = IERC20Metadata(tokenAddress).name();
    string memory symbol = IERC20Metadata(tokenAddress).symbol();
    uint8 decimals = IERC20Metadata(tokenAddress).decimals();
    logMetadataExtension(tokenAddress, name, symbol, decimals);
    emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
}
``` [1](#0-0) 

The emitted `LogMetadata` event is consumed by the NEAR bridge, which stores the reported `decimals` and `origin_decimals` in its persistent `token_decimals` map as a `Decimals` struct:

```rust
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
``` [2](#0-1) 

This map is keyed by `OmniAddress` and is the authoritative source for decimal normalization used during cross-chain amount conversion: [3](#0-2) 

The `DeployToken` path also stores `origin_decimals` from the metadata payload, confirming that stored decimals drive normalization: [4](#0-3) 

There is no mechanism to validate that the `decimals()` value returned by the token is stable, nor any guard preventing `logMetadata` from being called again for an already-registered token to overwrite the stored value.

---

### Impact Explanation

When the NEAR bridge normalizes an inbound EVM transfer amount, it uses the stored `origin_decimals` to scale the raw token units. If an attacker registers a token with `origin_decimals = 6` (correct), then causes the NEAR bridge to update to `origin_decimals = 18` (via a second `logMetadata` call after changing the token's `decimals()` return value), a deposit of `1e6` raw units (= 1 token at 6 decimals) is treated as `1e6 / 1e18 = 1e-12` tokens — severe under-minting. Conversely, registering with `origin_decimals = 18` then switching to `6` causes `1e18` raw units to be treated as `1e12` tokens — massive over-minting and theft of protocol liquidity. Both directions represent a critical balance manipulation affecting bridged funds.

---

### Likelihood Explanation

`logMetadata` is callable by any unprivileged address with no deposit requirement beyond `msg.value` (which can be zero). An attacker only needs to deploy a minimal upgradeable ERC20 whose `decimals()` selector returns a value they control. This is a standard Solidity pattern requiring no special privileges, leaked keys, or validator collusion. The attack is fully self-contained on-chain.

---

### Recommendation

1. **Restrict `logMetadata`** to a privileged role (e.g., `DEFAULT_ADMIN_ROLE`) or add a one-time registration guard that prevents re-registration of an already-stored token address.
2. **Snapshot and freeze decimals** at first registration; reject subsequent `logMetadata` calls for the same `tokenAddress` if decimals differ from the stored value.
3. **Validate decimal stability** by requiring that `decimals()` is called twice within the same transaction and returns the same value, or by requiring a time-lock before a decimal update takes effect.
4. **Audit the normalization logic** in the NEAR bridge's `fin_transfer` handler to confirm that stale `origin_decimals` cannot produce amounts larger than the actual deposited value.

---

### Proof of Concept

1. Attacker deploys `MaliciousToken` implementing `IERC20Metadata` where `decimals()` reads from a mutable storage slot, initially returning `6`.
2. Attacker calls `OmniBridge.logMetadata(address(MaliciousToken))`. NEAR bridge stores `origin_decimals = 6`.
3. Attacker calls `MaliciousToken.setDecimals(18)`, changing the return value of `decimals()`.
4. Attacker calls `OmniBridge.logMetadata(address(MaliciousToken))` again. NEAR bridge overwrites stored value with `origin_decimals = 18`.
5. Attacker calls `OmniBridge.initTransfer(address(MaliciousToken), 1e6, ...)` — depositing 1 token (6-decimal units).
6. NEAR bridge normalizes `1e6` raw units using stored `origin_decimals = 18`, computing an amount of `1e6 / 1e18 ≈ 0` — or, in the reverse direction, interprets `1e18` units as `1e12` tokens and mints accordingly, draining the protocol. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** near/omni-bridge/src/storage.rs (L131-136)
```rust
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```

**File:** near/omni-bridge/src/lib.rs (L228-228)
```rust
    pub token_decimals: LookupMap<OmniAddress, Decimals>,
```

**File:** near/omni-types/src/evm/events.rs (L138-155)
```rust
impl TryFromLog<Log<DeployToken>> for DeployTokenMessage {
    type Error = String;

    fn try_from_log(chain_kind: ChainKind, event: Log<DeployToken>) -> Result<Self, Self::Error> {
        Ok(Self {
            token: event.data.token.parse().map_err(stringify)?,
            token_address: OmniAddress::new_from_evm_address(
                chain_kind,
                H160(event.data.tokenAddress.into()),
            )?,
            decimals: event.data.decimals,
            origin_decimals: event.data.originDecimals,
            emitter_address: OmniAddress::new_from_evm_address(
                chain_kind,
                H160(event.address.into()),
            )?,
        })
    }
```
