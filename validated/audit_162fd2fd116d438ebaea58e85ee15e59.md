Audit Report

## Title
Nested `initializer` Modifier in `OmniBridge.initialize` Causes `OmniBridgeWormhole.initializeWormhole` to Revert, Leaving Proxy Permanently Uninitialized and Enabling Unauthorized Admin Takeover — (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

## Summary

`OmniBridgeWormhole.initializeWormhole` is marked `initializer` and internally calls `OmniBridge.initialize`, which is also marked `initializer`. Under OpenZeppelin v5 (the version in use), the nested `initializer` call unconditionally reverts with `InvalidInitialization()`, rolling back all state. The proxy is left with `_initialized = 0`. Because `OmniBridge.initialize` is `public`, any external caller can invoke it directly on the uninitialized proxy and seize `DEFAULT_ADMIN_ROLE`, enabling unauthorized minting and full bridge takeover.

## Finding Description

The project uses `@openzeppelin/contracts-upgradeable ^5.4.0`. [1](#0-0) 

`OmniBridgeWormhole.initializeWormhole` carries the `initializer` modifier and calls the parent `initialize` in its body: [2](#0-1) 

`OmniBridge.initialize` is also marked `initializer`: [3](#0-2) 

**OZ v5 `initializer` modifier execution trace on the proxy:**

When `initializeWormhole` is called:
- `isTopLevelCall = true` (`_initializing` is `false`)
- `initialized = 0`
- `initialSetup = true` → guard passes; sets `_initialized = 1`, `_initializing = true`
- Body executes and calls `initialize(...)`

When `initialize` is called from within the body:
- `isTopLevelCall = false` (`_initializing` is already `true`)
- `initialized = 1` (already written)
- `initialSetup = false` (`initialized != 0`)
- `construction = false` (`initialized == 1` but `address(this).code.length != 0` for a proxy)
- Both conditions false → **`revert InvalidInitialization()`**

The revert propagates up, rolling back all storage writes including `_initialized = 1`. The proxy is left with `_initialized = 0`.

The constructor calls `_disableInitializers()`, but this only writes to the **implementation** contract's ERC-7201 storage slot, not the proxy's storage: [4](#0-3) 

Because `initialize` is `public` and the proxy's `_initialized` remains `0`, any caller can invoke `initialize` directly on the proxy, passing arbitrary arguments including their own address as `nearBridgeDerivedAddress_`, and receive `DEFAULT_ADMIN_ROLE` via `_grantRole(DEFAULT_ADMIN_ROLE, _msgSender())`. [5](#0-4) 

## Impact Explanation

An attacker who calls `initialize` directly on the uninitialized proxy becomes `DEFAULT_ADMIN_ROLE`. They can then:

1. Call `setNearBridgeDerivedAddress(attackerEOA)` to replace the MPC-derived signer with their own address: [6](#0-5) 

2. Forge valid `finTransfer` signatures (since `ECDSA.recover` will now return their address) to mint arbitrary amounts of any bridge token to any recipient: [7](#0-6) 

3. Call `upgradeToken` / `_authorizeUpgrade` to replace token or bridge implementations with malicious ones. [8](#0-7) 

This constitutes unauthorized minting of bridged funds and a complete signer/prover verification bypass — matching the Critical allowed impact scope.

## Likelihood Explanation

The revert is deterministic and reproducible on every deployment attempt using `initializeWormhole`. Any deployment that calls `initializeWormhole` will fail, leaving the proxy uninitialized. A mempool observer or a bot scanning for UUPS proxies with `_initialized == 0` can immediately call `initialize` directly. No special privileges, victim interaction, or external conditions are required — only a public function call on an uninitialized proxy.

## Recommendation

Change `OmniBridge.initialize` to use `onlyInitializing` so it is safely callable from a child initializer, while `OmniBridgeWormhole.initializeWormhole` retains `initializer` as the single top-level entry point:

```diff
// OmniBridge.sol
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
-) public initializer {
+) public onlyInitializing {
```

Alternatively, inline the parent initialization logic directly into `initializeWormhole` and remove the standalone `initialize` function from `OmniBridge` entirely, or restrict `initialize` with an access control guard so it cannot be called directly on `OmniBridgeWormhole` proxies.

## Proof of Concept

1. Deploy `OmniBridgeWormhole` implementation (constructor calls `_disableInitializers()` on the implementation storage only).
2. Deploy an `ERC1967Proxy` pointing to the implementation with **empty calldata** (no initialization).
3. Call `proxy.initializeWormhole(tokenImpl, nearAddr, chainId, wormholeAddr, consistencyLevel)` → transaction reverts with `InvalidInitialization()`.
4. Confirm `proxy._initialized() == 0` (proxy storage is untouched).
5. Attacker calls `proxy.initialize(attackerAddr, attackerAddr, chainId)` → succeeds; attacker is now `DEFAULT_ADMIN_ROLE` and `nearBridgeDerivedAddress = attackerAddr`.
6. Attacker signs a `TransferMessagePayload` with their private key and calls `proxy.finTransfer(sig, payload)` with `recipient = attacker` and `tokenAddress = any bridge token` → `ECDSA.recover` returns `attackerAddr == nearBridgeDerivedAddress`, signature check passes, tokens are minted to the attacker.

### Citations

**File:** evm/package.json (L7-8)
```json
    "@openzeppelin/contracts": "^5.4.0",
    "@openzeppelin/contracts-upgradeable": "^5.4.0"
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L67-70)
```text
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L72-86)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L309-313)
```text
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L568-572)
```text
    function setNearBridgeDerivedAddress(
        address nearBridgeDerivedAddress_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    }
```
