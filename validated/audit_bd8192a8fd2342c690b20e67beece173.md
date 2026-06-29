### Title
`ECDSA.recover()` Result Not Checked for `address(0)` Enables Signature Bypass When `nearBridgeDerivedAddress` Is Zero - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.deployToken()` and `OmniBridge.finTransfer()` both call `ECDSA.recover()` and compare the result directly to `nearBridgeDerivedAddress` without checking whether the recovered address is `address(0)`. The `initialize()` function accepts `nearBridgeDerivedAddress_` without a zero-address guard. If the contract is initialized with `nearBridgeDerivedAddress = address(0)` (a realistic deployment error given the missing guard), an attacker can supply a crafted invalid signature that causes `ECDSA.recover()` to return `address(0)`, satisfying the equality check and bypassing signature verification entirely.

### Finding Description

Both critical entry points perform signature verification identically:

```solidity
// deployToken(), line 151
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}

// finTransfer(), line 311
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
``` [1](#0-0) [2](#0-1) 

Neither call checks whether the recovered address is `address(0)`. The `initialize()` function stores the caller-supplied `nearBridgeDerivedAddress_` without any zero-address validation:

```solidity
function initialize(
    address tokenImplementationAddress_,
    address nearBridgeDerivedAddress_,
    uint8 omniBridgeChainId_
) public initializer {
    tokenImplementationAddress = tokenImplementationAddress_;
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;   // no zero check
    ...
}
``` [3](#0-2) 

The same omission exists in `setNearBridgeDerivedAddress()`:

```solidity
function setNearBridgeDerivedAddress(
    address nearBridgeDerivedAddress_
) external onlyRole(DEFAULT_ADMIN_ROLE) {
    nearBridgeDerivedAddress = nearBridgeDerivedAddress_;  // no zero check
}
``` [4](#0-3) 

Under OpenZeppelin ECDSA v4.x (where `ECDSA.recover()` returns `address(0)` for malformed signatures rather than reverting), if `nearBridgeDerivedAddress` is `address(0)`, the equality `ECDSA.recover(...) != nearBridgeDerivedAddress` evaluates to `address(0) != address(0)` → `false`, so no revert occurs and the invalid signature is accepted as valid.

**Note on OZ version:** OZ v5 changed `ECDSA.recover()` to revert instead of returning `address(0)`. The exploitability of the bypass depends on which OZ version is linked. The missing zero-address guard in `initialize()` is the root cause regardless of OZ version; with OZ v4 it enables active exploitation, with OZ v5 it causes a permanent DoS on both functions if `nearBridgeDerivedAddress` is zero.

### Impact Explanation

If `nearBridgeDerivedAddress = address(0)` and OZ v4.x is in use:

- **`finTransfer()`**: An attacker can finalize arbitrary cross-chain transfers — minting bridge tokens or draining locked ERC-20/ETH/ERC-1155 assets to any `payload.recipient` they choose, with any `payload.amount`, for any `payload.tokenAddress`. This is unauthorized minting and theft of bridged funds.
- **`deployToken()`**: An attacker can deploy arbitrary bridge token contracts with attacker-controlled metadata, poisoning the `nearToEthToken` / `ethToNearToken` mappings and enabling subsequent fraudulent `finTransfer()` calls against those tokens. [5](#0-4) [6](#0-5) 

### Likelihood Explanation

The `initialize()` function is `public initializer` and accepts `nearBridgeDerivedAddress_` without validation. Deployment scripts, proxy upgrade flows, or misconfigured tooling can silently pass `address(0)`. The `setNearBridgeDerivedAddress()` admin setter has the same gap. Once deployed with a zero address, the window is open to any unprivileged caller who can craft a signature with `v ∉ {27,28}` or `s = 0` (standard techniques to force `ECDSA.recover()` to return `address(0)` under OZ v4). No special privilege is required after the deployment error occurs.

### Recommendation

1. Add a zero-address guard in `initialize()`:
```solidity
require(nearBridgeDerivedAddress_ != address(0), "Zero bridge address");
nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
```

2. Add the same guard in `setNearBridgeDerivedAddress()`.

3. Explicitly check the recovered signer in both `deployToken()` and `finTransfer()`:
```solidity
address signer = ECDSA.recover(hashed, signatureData);
if (signer == address(0) || signer != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
```

### Proof of Concept

Precondition: contract deployed with `nearBridgeDerivedAddress = address(0)` (OZ v4.x).

1. Attacker constructs a `TransferMessagePayload` with `recipient = attacker`, `amount = totalBridgedBalance`, `tokenAddress = someLockedToken`.
2. Attacker supplies a 65-byte `signatureData` with `v = 0` (or any value ≠ 27/28) — `ECDSA.recover()` under OZ v4 returns `address(0)`.
3. Attacker calls `finTransfer(signatureData, payload)`.
4. Check: `address(0) != address(0)` → `false` → no revert.
5. `completedTransfers[payload.destinationNonce]` is set to `true` and tokens are transferred to the attacker. [7](#0-6)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-195)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
        if (tokenImplementationAddress == address(0)) {
            revert TokenImplementationNotSet();
        }
        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
            Borsh.encodeString(metadata.token),
            Borsh.encodeString(metadata.name),
            Borsh.encodeString(metadata.symbol),
            bytes1(metadata.decimals)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }

        require(
            !isBridgeToken[nearToEthToken[metadata.token]],
            "ERR_TOKEN_EXIST"
        );
        uint8 decimals = _normalizeDecimals(metadata.decimals);

        // slither-disable-next-line reentrancy-no-eth
        address bridgeTokenProxy = address(
            new ERC1967Proxy(
                tokenImplementationAddress,
                abi.encodeWithSelector(
                    BridgeToken.initialize.selector,
                    metadata.name,
                    metadata.symbol,
                    decimals
                )
            )
        );

        deployTokenExtension(
            metadata.token,
            bridgeTokenProxy,
            decimals,
            metadata.decimals
        );

        emit BridgeTypes.DeployToken(
            bridgeTokenProxy,
            metadata.token,
            metadata.name,
            metadata.symbol,
            decimals,
            metadata.decimals
        );

        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);

        return bridgeTokenProxy;
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-367)
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

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }

        finTransferExtension(payload);

        emit BridgeTypes.FinTransfer(
            payload.originChain,
            payload.originNonce,
            payload.tokenAddress,
            payload.amount,
            payload.recipient,
            payload.feeRecipient
        );
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
