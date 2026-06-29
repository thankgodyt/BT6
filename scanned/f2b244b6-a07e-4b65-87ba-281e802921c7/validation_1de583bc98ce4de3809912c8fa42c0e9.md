### Title
`OmniBridge.initialize()` Marked `initializer` Instead of `onlyInitializing` Enables Uninitialized Wormhole State Leading to Permanent Fund Loss — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.initialize()` is declared `public initializer` rather than `onlyInitializing`. `OmniBridgeWormhole.initializeWormhole()` is also marked `initializer` and calls `initialize()` internally. Under OpenZeppelin v5 (the declared dependency), the `initializer` modifier does **not** permit re-entry from within another `initializer` call when the proxy is initialized in a separate transaction (two-step deployment). The nested call to `initialize()` always reverts, leaving `initializeWormhole()` permanently broken. The only viable initialization path becomes calling `initialize()` directly, which leaves `_wormhole = address(0)`. Every subsequent Wormhole message publishing call silently succeeds against `address(0)` — no VAA is ever published to NEAR — and user funds bridged through `initTransfer()` are permanently lost.

### Finding Description

`OmniBridge.initialize()` is `public initializer`: [1](#0-0) 

`OmniBridgeWormhole.initializeWormhole()` is also `initializer` and calls `initialize()`: [2](#0-1) 

The project uses `@openzeppelin/contracts-upgradeable ^5.4.0`: [3](#0-2) 

In OpenZeppelin v5, the `initializer` modifier evaluates two conditions to decide whether to allow execution:

- `initialSetup`: `initialized == 0 && isTopLevelCall` — false when called from within another `initializer` (because `_initialized` is already `1` and `isTopLevelCall` is `false`).
- `construction`: `initialized == 1 && address(this).code.length == 0` — false for a proxy initialized in a separate transaction (the proxy already has code).

When neither condition holds, OZ v5 reverts with `InvalidInitialization()`. Therefore, in a two-step deployment (proxy deployed first, then `initializeWormhole()` called in a separate transaction), `initializeWormhole()` always reverts at the inner `initialize()` call. The deployer is forced to call `initialize()` directly, which succeeds but leaves `_wormhole`, `_consistencyLevel`, and `wormholeNonce` at their zero values.

With `_wormhole = address(0)`, every extension hook that publishes a Wormhole message calls `address(0).publishMessage{value: value}(...)`. A call to `address(0)` in the EVM always returns success with empty return data; no VAA is ever emitted. The affected hooks are: [4](#0-3) [5](#0-4) 

The `initTransfer()` path in `OmniBridge` burns or locks the user's ERC-20 tokens and then calls `initTransferExtension()`: [6](#0-5) 

Because no VAA reaches NEAR, the NEAR `omni-bridge` contract never finalizes the inbound transfer, and the user's tokens are permanently locked/burned on the EVM side with no corresponding mint on NEAR.

A secondary, related issue is that `OmniBridgeWormhole` declares no `__gap` storage variable of its own, while `OmniBridge` ends with `uint256[49] private __gap`: [7](#0-6) 

`OmniBridgeWormhole` adds three storage variables (`_wormhole`, `_consistencyLevel`, `wormholeNonce`) immediately after `OmniBridge`'s gap with no reserved space: [8](#0-7) 

Any future upgrade that adds variables to `OmniBridgeWormhole` without a gap risks storage collisions with derived contracts. Similarly, `BridgeToken` declares no `__gap`, yet `HyperliquedBridgeToken` inherits it and appends `_systemAddress`: [9](#0-8) [10](#0-9) 

### Impact Explanation

Any user who calls `initTransfer()` on a misconfigured `OmniBridgeWormhole` proxy (where `_wormhole = address(0)`) has their ERC-20 tokens burned or locked on the EVM side. No Wormhole VAA is published, NEAR never processes the inbound transfer, and the tokens are permanently lost. This is a direct, unprivileged, user-triggered loss of bridged funds.

### Likelihood Explanation

The vulnerability is triggered whenever `OmniBridgeWormhole` is deployed using a two-step pattern (proxy deployed first, initialization in a separate transaction). This is a common deployment practice for auditability and multisig safety. The OZ v5 `initializer` semantics make `initializeWormhole()` silently unusable in this scenario, and the deployer has no obvious indication of the failure mode until funds are lost. The `initialize()` function being `public` makes it the natural fallback.

### Recommendation

1. Change `OmniBridge.initialize()` to `internal onlyInitializing` so it can only be invoked from within an active initializer context (e.g., `initializeWormhole()`). Expose a separate `public initializer` on `OmniBridge` itself for deployments that do not use the Wormhole variant.
2. Add a `uint256[N] private __gap` to `OmniBridgeWormhole` after its storage variables to reserve upgrade headroom.
3. Add a `uint256[N] private __gap` to `BridgeToken` after `_decimals` to protect `HyperliquedBridgeToken`'s `_systemAddress` from future `BridgeToken` upgrades.

### Proof of Concept

```
// Two-step deployment (common multisig/audit pattern):
OmniBridgeWormhole impl = new OmniBridgeWormhole();
// impl constructor calls _disableInitializers() — safe.

ERC1967Proxy proxy = new ERC1967Proxy(address(impl), "");
// proxy.code.length > 0 at this point.

// Attempt proper initialization — REVERTS in OZ v5:
proxy.initializeWormhole(implAddr, nearAddr, chainId, wormholeAddr, level);
// → OmniBridge.initialize() is called with _initializing=true, _initialized=1
// → initialSetup = false, construction = false → InvalidInitialization()

// Deployer falls back to the only non-reverting path:
proxy.initialize(implAddr, nearAddr, chainId);
// → succeeds; _wormhole = address(0)

// User bridges tokens:
proxy.initTransfer(token, amount, fee, nativeFee, "near:alice.near", "");
// → tokens burned on EVM
// → initTransferExtension calls address(0).publishMessage{value:...}(...)
// → call succeeds, no VAA emitted, NEAR never sees the transfer
// → user's tokens are permanently lost
```

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L404-426)
```text
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L598-598)
```text
    uint256[49] private __gap;
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L27-30)
```text
    IWormhole private _wormhole;
    // https://wormhole.com/docs/build/reference/consistency-levels
    uint8 private _consistencyLevel;
    uint32 public wormholeNonce;
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L96-116)
```text
    function finTransferExtension(
        BridgeTypes.TransferMessagePayload memory payload
    ) internal override {
        bytes memory messagePayload = bytes.concat(
            bytes1(uint8(MessageType.FinTransfer)),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            Borsh.encodeString(payload.feeRecipient)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            messagePayload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L118-150)
```text
    function initTransferExtension(
        address sender,
        address tokenAddress,
        uint64 originNonce,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message,
        uint256 value
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.InitTransfer)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(sender),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeUint64(originNonce),
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
            Borsh.encodeUint128(nativeFee),
            Borsh.encodeString(recipient),
            Borsh.encodeString(message)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```

**File:** evm/package.json (L7-9)
```json
    "@openzeppelin/contracts": "^5.4.0",
    "@openzeppelin/contracts-upgradeable": "^5.4.0"
  },
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L35-36)
```text
    address internal _systemAddress;
    bytes32 constant HYPER_CORE_DEPLOYER_SLOT = keccak256("HyperCore deployer");
```

**File:** evm/src/omni-bridge/contracts/BridgeToken.sol (L17-19)
```text
    string internal _name;
    string internal _symbol;
    uint8 internal _decimals;
```
