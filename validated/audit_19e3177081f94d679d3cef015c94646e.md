Audit Report

## Title
Nested `initializer` Modifier in `OmniBridgeWormhole.initializeWormhole` Causes Permanent Revert, Leaving Proxy Uninitialized and Enabling Unauthorized `DEFAULT_ADMIN_ROLE` Seizure — (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

## Summary

`OmniBridgeWormhole.initializeWormhole` is marked `initializer` and internally calls `OmniBridge.initialize`, which is also marked `initializer`. Under OpenZeppelin Upgradeable v5 (the version in use), a nested `initializer`-within-`initializer` call deterministically reverts with `InvalidInitialization`, rolling back the entire transaction and leaving the proxy with `_initialized = 0`. Because `OmniBridge.initialize` is `public`, any external caller can invoke it directly on the uninitialized proxy and seize `DEFAULT_ADMIN_ROLE`, enabling unauthorized minting of bridge tokens and full protocol takeover.

## Finding Description

**Root cause — OZ v5 `initializer` modifier semantics:**

`evm/package.json` pins `@openzeppelin/contracts-upgradeable: ^5.4.0`. In OZ v5, the `initializer` modifier evaluates two conditions before proceeding:

```
initialSetup  = (_initialized == 0) && isTopLevelCall
construction  = (_initialized == 1) && (address(this).code.length == 0)
```

If neither is true, it reverts with `InvalidInitialization`.

**Call sequence on the proxy:**

1. `initializeWormhole(...)` is called. Its `initializer` modifier fires: `isTopLevelCall = true`, `_initialized = 0` → `initialSetup = true`. It sets `_initialized = 1` and `_initializing = true`, then enters the function body.
2. Inside the body, `initialize(...)` is called. Its `initializer` modifier fires: `isTopLevelCall = false` (because `_initializing` is already `true`), `_initialized = 1` → `initialSetup = false`; `address(this).code.length != 0` for a proxy → `construction = false`. **Reverts with `InvalidInitialization`.**
3. The entire transaction rolls back. The proxy storage is unchanged: `_initialized = 0`.

**Exploit path:**

Because `OmniBridge.initialize` is `public` and the proxy remains at `_initialized = 0`, any caller can invoke it directly:

```
proxy.initialize(attacker, attacker, chainId)
```

This succeeds, granting the attacker `DEFAULT_ADMIN_ROLE` and `PAUSABLE_ADMIN_ROLE` via `_grantRole`.

The constructor's `_disableInitializers()` call only protects the implementation contract's own storage; the proxy's storage slot for `_initialized` is independent and starts at zero.

## Impact Explanation

With `DEFAULT_ADMIN_ROLE` the attacker can:

- Call `setNearBridgeDerivedAddress(attackerEOA)` to replace the MPC-derived signer with their own address, bypassing the ECDSA signature check in `finTransfer` and `deployToken`.
- Call `finTransfer` with a self-signed payload to mint arbitrary amounts of any bridge token to any recipient (unauthorized minting of bridged funds).
- Call `upgradeToken` / `_authorizeUpgrade` to replace token or bridge implementations with malicious contracts.
- Drain all ERC-20 tokens held in escrow by the bridge.

This matches the allowed critical impact: **unauthorized minting, role/authorization bypass, and signer verification bypass enabling invalid finalization**.

## Likelihood Explanation

The revert is deterministic and reproducible on every deployment attempt using `initializeWormhole`. Any deployment script that calls this function will fail, leaving the proxy permanently uninitialized. A mempool observer or a bot scanning for UUPS proxies with `_initialized == 0` can call `initialize` immediately after the failed deployment transaction is mined. No special privileges, victim interaction, or external conditions are required — only a public function call.

## Recommendation

Change `OmniBridge.initialize` to use `onlyInitializing` so it can be safely called from within a child `initializer`:

```diff
 function initialize(
     address tokenImplementationAddress_,
     address nearBridgeDerivedAddress_,
     uint8 omniBridgeChainId_
-) public initializer {
+) public onlyInitializing {
```

`OmniBridgeWormhole.initializeWormhole` retains `initializer` as the single top-level entry point. Alternatively, inline the parent initialization logic directly into `initializeWormhole` and remove the standalone `initialize` function from `OmniBridge` entirely, eliminating the public entry point.

## Proof of Concept

1. Deploy `OmniBridgeWormhole` implementation (constructor calls `_disableInitializers()` on the implementation).
2. Deploy `ERC1967Proxy` pointing to the implementation with empty calldata — proxy `_initialized = 0`.
3. Call `proxy.initializeWormhole(tokenImpl, nearAddr, chainId, wormholeAddr, consistencyLevel)` → reverts with `InvalidInitialization`; proxy `_initialized` remains `0`.
4. Attacker calls `proxy.initialize(attackerAddr, attackerAddr, chainId)` → succeeds; attacker holds `DEFAULT_ADMIN_ROLE`.
5. Attacker calls `proxy.setNearBridgeDerivedAddress(attackerEOA)`.
6. Attacker constructs a valid `TransferMessagePayload`, signs it with their private key, and calls `proxy.finTransfer(sig, payload)` with `recipient = attacker` → `ECDSA.recover` returns `attackerEOA == nearBridgeDerivedAddress` → tokens minted to attacker. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L568-572)
```text
    function setNearBridgeDerivedAddress(
        address nearBridgeDerivedAddress_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    }
```

**File:** evm/package.json (L7-8)
```json
    "@openzeppelin/contracts": "^5.4.0",
    "@openzeppelin/contracts-upgradeable": "^5.4.0"
```
