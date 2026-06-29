### Title
Missing Storage Gap in `BridgeToken` Corrupts `HyperliquedBridgeToken._systemAddress` on Upgrade - (File: evm/src/omni-bridge/contracts/BridgeToken.sol, evm/src/omni-bridge/contracts/HlBridgeToken.sol)

### Summary

`BridgeToken` is an upgradeable parent contract that declares storage variables but defines no `__gap`. `HyperliquedBridgeToken` inherits `BridgeToken` and appends `_systemAddress` as a regular storage variable immediately after `BridgeToken`'s slots. If `BridgeToken` is ever upgraded to add new storage variables, `_systemAddress` shifts to a different slot, corrupting the access-control guard of `coreReceiveWithData` and the token-accounting logic that depends on it.

### Finding Description

`BridgeToken` declares three storage variables with no trailing gap:

```
_name    (slot N)
_symbol  (slot N+1)
_decimals (slot N+2)
// no __gap
``` [1](#0-0) 

`HyperliquedBridgeToken` inherits `BridgeToken` and appends `_systemAddress` at the next available slot:

```
_systemAddress (slot N+3)
``` [2](#0-1) 

`OmniBridge` exposes `upgradeToken`, which lets the admin push a new implementation to any registered bridge token proxy: [3](#0-2) 

If a future `BridgeToken` implementation adds even one new storage variable (e.g., a fee flag, a blacklist mapping, a version counter), the Solidity storage layout shifts every slot that `HyperliquedBridgeToken` owns. `_systemAddress` would then read from the wrong slot — either `address(0)` or whatever bytes happen to occupy that slot.

`OmniBridge` itself correctly reserves a gap: [4](#0-3) 

`BridgeToken` and `HyperliquedBridgeToken` have no equivalent protection. [5](#0-4) 

### Impact Explanation

`_systemAddress` is the sole access-control guard for `coreReceiveWithData`: [6](#0-5) 

It is also the source account for the internal token pool used in both dispatch paths: [7](#0-6) 

If `_systemAddress` is corrupted to `address(0)`, the `NotSystemAddress` revert fires for every legitimate HyperCore callback, permanently freezing the HyperCore→HyperEVM and HyperCore→NEAR bridge paths for all users of that token.

If `_systemAddress` is corrupted to a non-zero value that an attacker controls (e.g., the slot now holds a mapping key or a counter that the attacker can influence), the attacker passes the `msg.sender != _systemAddress` check and can call `coreReceiveWithData` freely. The `ACTION_TRANSFER` path moves tokens from the (now attacker-controlled) `_systemAddress` to any recipient; the `ACTION_INIT_TRANSFER` path calls `OmniBridge.initTransfer` on behalf of the token contract, initiating unauthorized cross-chain transfers. Either path results in theft or permanent loss of bridged funds.

### Likelihood Explanation

`BridgeToken` is explicitly designed to be upgraded: `OmniBridge.upgradeToken` is a documented admin operation, and `BridgeToken` already overrides `_authorizeUpgrade`. Any routine maintenance upgrade that adds a new field to `BridgeToken` (e.g., a per-token fee, a pause flag, a metadata version) silently corrupts every `HyperliquedBridgeToken` proxy that is subsequently upgraded. The developer has no on-chain warning; the storage layout mismatch is invisible until the corrupted `_systemAddress` is read at runtime.

### Recommendation

Add a `__gap` array at the end of `BridgeToken`'s storage declarations, sized to leave room for future variables:

```solidity
// BridgeToken.sol — after _decimals
uint256[47] private __gap;
```

Add a separate `__gap` at the end of `HyperliquedBridgeToken`'s storage declarations:

```solidity
// HlBridgeToken.sol — after _systemAddress
uint256[49] private __gap;
```

The combined slot count for each contract (existing variables + gap) should sum to a round number (e.g., 50) so that future additions consume gap slots rather than shifting child-contract storage.

### Proof of Concept

1. Deploy `HyperliquedBridgeToken` proxy. `_systemAddress` is stored at slot `N+3` (after `_name`, `_symbol`, `_decimals` inherited from `BridgeToken`).
2. Admin calls `OmniBridge.upgradeToken(hlTokenProxy, newBridgeTokenImpl)` where `newBridgeTokenImpl` is a `BridgeToken` that adds one new `uint256 feeRate` variable after `_decimals`.
3. `_systemAddress` in the proxy's storage is now read from slot `N+4`, but the proxy's storage still holds the old `_systemAddress` value at slot `N+3`. Slot `N+4` contains `0` (uninitialized) or an unrelated value.
4. Any call from the legitimate HyperCore system address to `coreReceiveWithData` reverts with `NotSystemAddress` (if slot `N+4` is `address(0)`), permanently freezing the bridge path — or, if slot `N+4` holds an attacker-controlled value, the attacker bypasses the guard and drains the token pool via `ACTION_TRANSFER`.

### Citations

**File:** evm/src/omni-bridge/contracts/BridgeToken.sol (L10-24)
```text
contract BridgeToken is
    Initializable,
    UUPSUpgradeable,
    ERC20Upgradeable,
    Ownable2StepUpgradeable,
    IBridgeToken
{
    string internal _name;
    string internal _symbol;
    uint8 internal _decimals;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L35-36)
```text
    address internal _systemAddress;
    bytes32 constant HYPER_CORE_DEPLOYER_SLOT = keccak256("HyperCore deployer");
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L113-115)
```text
    ) external override {
        if (msg.sender != _systemAddress) revert NotSystemAddress();
        if (data.length == 0) revert EmptyActionData();
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L120-135)
```text
        if (action == ACTION_TRANSFER) {
            address recipient = abi.decode(tail, (address));
            _update(_systemAddress, recipient, amount);
        } else if (action == ACTION_INIT_TRANSFER) {
            (uint128 fee, string memory recipient, string memory message) = abi
                .decode(tail, (uint128, string, string));
            uint128 amount128 = amount.toUint128();
            _update(_systemAddress, address(this), amount);
            IOmniBridgeInitTransfer(owner()).initTransfer(
                address(this),
                amount128,
                fee,
                0,
                recipient,
                message
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L559-566)
```text
    function upgradeToken(
        address tokenAddress,
        address implementation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(isBridgeToken[tokenAddress], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken proxy = BridgeToken(tokenAddress);
        proxy.upgradeToAndCall(implementation, bytes(""));
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L598-598)
```text
    uint256[49] private __gap;
```
