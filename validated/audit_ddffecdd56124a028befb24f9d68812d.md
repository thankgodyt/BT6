### Title
`OmniBridge.initialize()` Uses `initializer` Instead of `onlyInitializing`, Blocking `OmniBridgeWormhole` Deployment - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary

`OmniBridge` is a base contract intended to be inherited by `OmniBridgeWormhole`. Its `initialize()` function incorrectly uses the `initializer` modifier instead of `onlyInitializing`. When `OmniBridgeWormhole.initializeWormhole()` (also marked `initializer`) calls `OmniBridge.initialize()`, the OpenZeppelin v5 `Initializable` guard detects a re-entrant initializer call and reverts with `InvalidInitialization()`, making `OmniBridgeWormhole` permanently undeployable through any standard proxy path.

### Finding Description

`OmniBridge` is deployed as a UUPS upgradeable proxy and is also the parent of `OmniBridgeWormhole`. [1](#0-0) 

`OmniBridge.initialize()` carries the `initializer` modifier. `OmniBridgeWormhole` inherits `OmniBridge` and provides its own entry-point: [2](#0-1) 

`initializeWormhole` is also marked `initializer` and immediately calls `initialize()` from the parent. Under OpenZeppelin Contracts-Upgradeable v5 (the version pinned in the project): [3](#0-2) 

The `initializer` modifier sets `_initialized = 1` and `_initializing = true` when `initializeWormhole` begins. When the body then calls `OmniBridge.initialize()`, the modifier re-evaluates:

- `isTopLevelCall = !_initializing = false`
- `initialSetup = (_initialized == 0 && isTopLevelCall) = false`
- `construction = (_initialized == 1 && !isContract(address(this))) = false` (proxy IS a contract)

Both guards are false → `revert InvalidInitialization()`.

The entire proxy deployment transaction reverts. If a deployer instead deploys the proxy without initialization data and then attempts `initializeWormhole` separately (a common workaround attempt), the proxy remains with `_initialized = 0`, allowing any external caller to invoke `OmniBridge.initialize()` directly and seize `DEFAULT_ADMIN_ROLE` and `PAUSABLE_ADMIN_ROLE` over the bridge.

### Impact Explanation

`OmniBridgeWormhole` cannot be initialized through any supported proxy path. If a deployer works around the failure by separating proxy deployment from initialization, the uninitialized proxy is open to admin takeover: an attacker who calls `initialize()` first gains full control, can set `nearBridgeDerivedAddress` to an address they control, forge valid signatures accepted by `finTransfer`/`deployToken`, and mint arbitrary bridge tokens or drain escrowed assets.

### Likelihood Explanation

The bug triggers on every deployment attempt of `OmniBridgeWormhole`. The Wormhole integration is a production deployment target (hardhat tasks and tests exist for it). Any deployer who encounters the revert and attempts a two-step deployment creates the exploitable window. [4](#0-3) 

### Recommendation

Change `OmniBridge.initialize()` to use `onlyInitializing` so it can be safely called from within a child's `initializer` scope:

```diff
- ) public initializer {
+ ) public onlyInitializing {
``` [5](#0-4) 

### Proof of Concept

1. Deploy `OmniBridgeWormhole` implementation (constructor calls `_disableInitializers()`).
2. Deploy an `ERC1967Proxy` pointing to the implementation with `initializeWormhole` calldata.
3. Transaction reverts with `InvalidInitialization()` because `OmniBridge.initialize()` (marked `initializer`) is called while `_initializing = true` and `_initialized = 1`.
4. Alternatively: deploy the proxy with empty init data, then call `initializeWormhole` → same revert. Proxy is now live with `_initialized = 0`.
5. Attacker calls `OmniBridge.initialize(anyImpl, attackerAddress, 0)` directly on the proxy → succeeds, attacker holds `DEFAULT_ADMIN_ROLE`.
6. Attacker sets `nearBridgeDerivedAddress` to their own key, signs arbitrary `finTransfer` payloads, and mints bridge tokens to themselves. [6](#0-5) [2](#0-1)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L67-86)
```text
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address tokenImplementationAddress_,
        address nearBridgeDerivedAddress_,
        uint8 omniBridgeChainId_
    ) public initializer {
        tokenImplementationAddress = tokenImplementationAddress_;
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
        omniBridgeChainId = omniBridgeChainId_;

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init_unchained();
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(PAUSABLE_ADMIN_ROLE, _msgSender());
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L26-46)
```text
contract OmniBridgeWormhole is OmniBridge {
    IWormhole private _wormhole;
    // https://wormhole.com/docs/build/reference/consistency-levels
    uint8 private _consistencyLevel;
    uint32 public wormholeNonce;

    function initializeWormhole(
        address tokenImplementationAddress,
        address nearBridgeDerivedAddress,
        uint8 omniBridgeChainId,
        address wormholeAddress,
        uint8 consistencyLevel
    ) external initializer {
        initialize(
            tokenImplementationAddress,
            nearBridgeDerivedAddress,
            omniBridgeChainId
        );
        _wormhole = IWormhole(wormholeAddress);
        _consistencyLevel = consistencyLevel;
    }
```

**File:** evm/package.json (L8-8)
```json
    "@openzeppelin/contracts-upgradeable": "^5.4.0"
```
