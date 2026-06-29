Audit Report

## Title
`OmniBridge.initialize()` Uses `initializer` Instead of `onlyInitializing`, Blocking `OmniBridgeWormhole` Initialization and Enabling Admin Takeover - (File: evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol)

## Summary

`OmniBridgeWormhole.initializeWormhole()` is marked `initializer` and calls `OmniBridge.initialize()`, which is also marked `initializer`. Under OpenZeppelin Contracts-Upgradeable v5 (`^5.4.0`), a nested `initializer`-to-`initializer` call reverts with `InvalidInitialization()`, making `OmniBridgeWormhole` impossible to initialize through any standard proxy path. A two-step deployment workaround leaves the proxy live but uninitialized, allowing any external caller to seize `DEFAULT_ADMIN_ROLE` and take full control of the bridge.

## Finding Description

`OmniBridge.initialize()` carries the `initializer` modifier: [1](#0-0) 

`OmniBridgeWormhole.initializeWormhole()` is also marked `initializer` and immediately calls `initialize()`: [2](#0-1) 

Under OZ v5 `Initializable`, when `initializeWormhole` begins execution, the `initializer` modifier sets `_initialized = 1` and `_initializing = true`. When the body then calls `OmniBridge.initialize()`, the `initializer` modifier re-evaluates:

- `isTopLevelCall = !_initializing = false`
- `initialSetup = (_initialized == 0 && isTopLevelCall) = false`
- `construction = (_initialized == 1 && address(this).code.length == 0) = false` (proxy is a deployed contract)

Both guards are false → `revert InvalidInitialization()`. The project pins `@openzeppelin/contracts-upgradeable: ^5.4.0`: [3](#0-2) 

**Exploit path for admin takeover:**
1. Deployer deploys `ERC1967Proxy` pointing to `OmniBridgeWormhole` implementation with empty init data (step 1 succeeds; `_initialized` remains `0`).
2. Deployer calls `initializeWormhole(...)` — reverts with `InvalidInitialization()`. Proxy is now live and permanently uninitialized.
3. Attacker calls `OmniBridge.initialize(anyImpl, attackerAddress, 0)` directly on the proxy. This succeeds because `_initialized == 0` and `_initializing == false`.
4. Attacker holds `DEFAULT_ADMIN_ROLE` and `PAUSABLE_ADMIN_ROLE`.
5. Attacker calls `setNearBridgeDerivedAddress(attackerControlledKey)`, then forges valid ECDSA signatures accepted by `finTransfer` and `deployToken`, minting arbitrary bridge tokens or draining escrowed assets. [4](#0-3) [5](#0-4) 

## Impact Explanation

An attacker who calls `OmniBridge.initialize()` on the uninitialized proxy gains `DEFAULT_ADMIN_ROLE`, can redirect `nearBridgeDerivedAddress` to a key they control, and can then forge signatures accepted by `finTransfer` (unauthorized minting of bridge tokens to arbitrary recipients) and `deployToken` (unauthorized token deployment). This matches the critical impact scope: **unauthorized role bypass enabling unauthorized minting and draining of bridged funds**.

## Likelihood Explanation

The revert is deterministic and triggered on every standard deployment attempt of `OmniBridgeWormhole`. A deployer who encounters the revert and attempts a two-step deployment (proxy first, then init) creates the exploitable window. The Wormhole integration is a production deployment target with existing hardhat tasks and tests. The attacker's action — calling a public `initialize()` function on an uninitialized proxy — requires no special privileges.

## Recommendation

Change `OmniBridge.initialize()` to use `onlyInitializing` so it can be safely called from within a child's `initializer` scope:

```diff
- ) public initializer {
+ ) public onlyInitializing {
```

This allows `initializeWormhole` (marked `initializer`) to call the parent `initialize()` without triggering the re-entrancy guard, while still preventing direct external calls to `OmniBridge.initialize()` outside of an initializer context.

## Proof of Concept

1. Deploy `OmniBridgeWormhole` implementation (constructor calls `_disableInitializers()`).
2. Deploy `ERC1967Proxy` with empty init data → succeeds, `_initialized = 0`.
3. Call `initializeWormhole(impl, deployer, 1, wormhole, 1)` → reverts with `InvalidInitialization()`. Proxy is live and uninitialized.
4. Attacker calls `OmniBridge.initialize(anyImpl, attackerAddress, 0)` on the proxy → succeeds, attacker holds `DEFAULT_ADMIN_ROLE`.
5. Attacker calls `setNearBridgeDerivedAddress(attackerKey)`.
6. Attacker constructs and signs a `TransferMessagePayload` with `attackerKey`, calls `finTransfer` → signature validates, bridge mints tokens to attacker.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L72-76)
```text
    function initialize(
        address tokenImplementationAddress_,
        address nearBridgeDerivedAddress_,
        uint8 omniBridgeChainId_
    ) public initializer {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L311-313)
```text
        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L568-572)
```text
    function setNearBridgeDerivedAddress(
        address nearBridgeDerivedAddress_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L32-46)
```text
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
