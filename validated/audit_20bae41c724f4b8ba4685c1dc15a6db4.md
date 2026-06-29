### Title
Incorrect `initializer` Modifier in Parent `OmniBridge.initialize` Prevents `OmniBridgeWormhole` Initialization, Enabling Unauthorized Admin Takeover — (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

---

### Summary

`OmniBridgeWormhole.initializeWormhole` uses the `initializer` modifier and internally calls `OmniBridge.initialize`, which also uses the `initializer` modifier. OpenZeppelin's `Initializable` logic causes the nested call to revert, making the proxy permanently uninitializable through the intended path. Because `OmniBridge.initialize` is `public`, an attacker can call it directly on the uninitialized proxy and seize `DEFAULT_ADMIN_ROLE`.

---

### Finding Description

`OmniBridgeWormhole` inherits from `OmniBridge`. Its initialization function calls the parent's `initialize`:

```solidity
// OmniBridgeWormhole.sol line 32-46
function initializeWormhole(...) external initializer {
    initialize(                          // calls parent — also marked initializer
        tokenImplementationAddress,
        nearBridgeDerivedAddress,
        omniBridgeChainId
    );
    _wormhole = IWormhole(wormholeAddress);
    _consistencyLevel = consistencyLevel;
}
``` [1](#0-0) 

The parent function is:

```solidity
// OmniBridge.sol line 72-86
function initialize(...) public initializer {
    ...
    _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
    ...
}
``` [2](#0-1) 

When `initializeWormhole` is called, OpenZeppelin's `initializer` modifier sets `_initializing = true` and `_initialized = 1` before executing the body. When `initialize()` is then called inside the body, the `initializer` modifier re-evaluates: `isTopLevelCall = false` (because `_initializing` is already `true`) and `_initialized` is already `1`, so the condition `initialSetup = false` and `construction = false` — causing an `InvalidInitialization` revert (OZ v5) or `"Initializable: contract is already initialized"` revert (OZ v4). The entire transaction rolls back, leaving `_initialized = 0`.

Because `OmniBridge.initialize` is `public`, any caller can invoke it directly on the proxy while it remains uninitialized.

---

### Impact Explanation

An attacker who calls `OmniBridge.initialize` directly on an uninitialized `OmniBridgeWormhole` proxy becomes `DEFAULT_ADMIN_ROLE`. With that role they can:

1. Call `setNearBridgeDerivedAddress()` to replace the MPC-derived signer address with their own EOA.
2. Forge valid `finTransfer` signatures (since `ECDSA.recover` will now match their address) to mint arbitrary amounts of any bridge token to any recipient.
3. Call `upgradeToken` / `upgradeToAndCall` to replace the implementation with a malicious one.
4. Drain all ERC-20 tokens locked in the bridge.

This is a complete, unauthorized takeover of the Wormhole-routed bridge (Arbitrum, Base, Polygon, BNB chains). [3](#0-2) [4](#0-3) 

---

### Likelihood Explanation

The revert is deterministic and reproducible on every deployment attempt. Any deployment script that calls `initializeWormhole` will fail. The proxy is then left with `_initialized = 0` and `initialize()` callable by anyone. A mempool observer or a bot scanning for uninitialized UUPS proxies can front-run or simply call `initialize()` after the failed deployment transaction.

---

### Recommendation

Change `OmniBridge.initialize` to use `onlyInitializing` so it can be safely called from a child initializer:

```diff
// OmniBridge.sol
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
-) public initializer {
+) public onlyInitializing {
```

`OmniBridgeWormhole.initializeWormhole` retains the `initializer` modifier as the single top-level entry point. Alternatively, inline the parent's initialization logic directly into `initializeWormhole` and remove the standalone `initialize` function from `OmniBridge` entirely.

---

### Proof of Concept

1. Deploy an `ERC1967Proxy` pointing to `OmniBridgeWormhole` implementation with empty calldata (no init).
2. Call `proxy.initializeWormhole(...)` → transaction reverts with `InvalidInitialization`.
3. Confirm `proxy._initialized() == 0` (proxy is uninitialized).
4. Attacker calls `proxy.initialize(attackerAddress, attackerAddress, chainId)` → succeeds; attacker is now `DEFAULT_ADMIN_ROLE`.
5. Attacker calls `proxy.setNearBridgeDerivedAddress(attackerEOA)`.
6. Attacker signs a `TransferMessagePayload` with their private key and calls `proxy.finTransfer(sig, payload)` with `recipient = attacker`, minting tokens to themselves. [5](#0-4) [6](#0-5)

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L309-312)
```text
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L568-572)
```text
    function setNearBridgeDerivedAddress(
        address nearBridgeDerivedAddress_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    }
```
