### Title
Unprotected `initialize()` Grants Full Admin Control to Any Caller — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initialize()` is declared `public` with no caller restriction. Any address that calls it first on a freshly deployed proxy becomes the holder of `DEFAULT_ADMIN_ROLE` and `PAUSABLE_ADMIN_ROLE`. Because `DEFAULT_ADMIN_ROLE` controls `setNearBridgeDerivedAddress()` — the function that sets the MPC-derived signer used to authenticate every cross-chain `finTransfer` and `deployToken` message — an attacker who wins the initialization race can subsequently forge valid bridge signatures and mint unlimited bridge tokens.

---

### Finding Description

`OmniBridge.initialize()` is marked `public initializer` with no access-control modifier:

```solidity
// OmniBridge.sol lines 72-86
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
) public initializer {
    ...
    _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
    _grantRole(PAUSABLE_ADMIN_ROLE, _msgSender());
}
``` [1](#0-0) 

The OpenZeppelin `initializer` modifier only prevents the function from being called more than once; it does not restrict *who* may call it. The implementation contract is protected by `_disableInitializers()` in the constructor:

```solidity
constructor() {
    _disableInitializers();
}
``` [2](#0-1) 

However, the proxy contract itself has no such protection. If the proxy is deployed in one transaction and `initialize()` is called in a subsequent transaction — a common two-step deployment pattern — an attacker can front-run the initialization call and become the sole `DEFAULT_ADMIN_ROLE` holder.

The same pattern is present in `OmniBridgeWormhole.initializeWormhole()`, which is `external initializer` with no access control and internally calls `initialize()`:

```solidity
function initializeWormhole(...) external initializer {
    initialize(tokenImplementationAddress, nearBridgeDerivedAddress, omniBridgeChainId);
    ...
}
``` [3](#0-2) 

---

### Impact Explanation

`DEFAULT_ADMIN_ROLE` controls the following critical functions:

1. **`setNearBridgeDerivedAddress()`** — replaces the MPC-derived Ethereum address used to verify ECDSA signatures in both `finTransfer()` and `deployToken()`:

```solidity
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
``` [4](#0-3) 

2. **`_authorizeUpgrade()`** — allows upgrading the proxy to an arbitrary malicious implementation. [5](#0-4) 

3. **`upgradeToken()`** — upgrades any deployed `BridgeToken` proxy to a malicious implementation. [6](#0-5) 

An attacker who controls `DEFAULT_ADMIN_ROLE` calls `setNearBridgeDerivedAddress(attackerEOA)`. They can then self-sign any `finTransfer` payload and call `finTransfer()` to mint unlimited bridge tokens to any recipient, or drain all ERC-20 tokens held in escrow by the bridge. This constitutes unauthorized minting and permanent loss of all bridged funds.

---

### Likelihood Explanation

Front-running `initialize()` on a UUPS proxy is a well-documented and actively exploited attack class on EVM chains. The attack requires only:

1. Monitoring the mempool for a proxy deployment transaction that does not atomically encode initialization data.
2. Submitting a higher-gas `initialize()` call with attacker-controlled parameters before the deployer's transaction is mined.

No privileged access, leaked keys, or off-chain compromise is required. The attacker is a standard public smart-contract caller. The vulnerability window exists for the entire duration between proxy deployment and the legitimate `initialize()` call.

---

### Recommendation

Pass the initialization calldata directly to the `ERC1967Proxy` constructor so that deployment and initialization are atomic and cannot be front-run:

```solidity
new ERC1967Proxy(
    implementationAddress,
    abi.encodeWithSelector(OmniBridge.initialize.selector, ...)
);
```

Alternatively, add an `onlyOwner` or deployer-address check to `initialize()`, or use OpenZeppelin's `Ownable` pattern where the deployer is set in the constructor before the proxy is initialized.

---

### Proof of Concept

1. Deployer broadcasts **Tx A**: `new ERC1967Proxy(omniBridgeImpl, "")` — proxy deployed with empty init data, `initialize()` not yet called.
2. Attacker observes Tx A in the mempool and broadcasts **Tx B** (higher gas):
   ```solidity
   OmniBridge(proxyAddress).initialize(
       tokenImpl,
       attackerAddress,   // nearBridgeDerivedAddress set to attacker's EOA
       chainId
   );
   ```
3. Tx B mines first. Attacker now holds `DEFAULT_ADMIN_ROLE`; `nearBridgeDerivedAddress == attackerAddress`.
4. Attacker constructs a valid-looking `TransferMessagePayload` for any bridge token and signs it with their private key.
5. Attacker calls `finTransfer(attackerSignature, payload)`. `ECDSA.recover(hashed, attackerSignature) == nearBridgeDerivedAddress` passes.
6. `IBridgeToken(payload.tokenAddress).mint(attacker, unlimitedAmount)` executes — unlimited unauthorized minting of any bridge token. [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L68-70)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L151-153)
```text
        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-313)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L594-596)
```text
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
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
