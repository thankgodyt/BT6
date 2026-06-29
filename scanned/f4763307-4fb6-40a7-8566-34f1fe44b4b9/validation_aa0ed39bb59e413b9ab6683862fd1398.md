### Title
Unrestricted `receive()` Function Permanently Locks ETH With No Recovery Path - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
`OmniBridge.sol` contains a completely unrestricted `receive()` function that silently accepts ETH from any caller. Because no admin rescue or withdrawal function exists for ETH, any ETH delivered via this path is permanently frozen in the contract.

### Finding Description
The contract's `receive()` function at line 574 carries no guard whatsoever:

```solidity
receive() external payable {}
``` [1](#0-0) 

The only legitimate ETH inflow path is through `initTransfer()` (which is `payable` and records the transfer on-chain), and the only ETH outflow path is through `finTransfer()` when `payload.tokenAddress == address(0)`, which requires a valid MPC-signed payload: [2](#0-1) 

ETH that arrives via `receive()` is never registered as a pending transfer, so it can never be released through `finTransfer()`. A full audit of the contract reveals no `rescueETH`, `withdrawETH`, `emergencyWithdraw`, or any other admin function capable of recovering ETH held by the contract: [3](#0-2) 

### Impact Explanation
Any ETH sent directly to the contract address — whether by a user who mistakes the bridge contract for a payable endpoint, by an external integration, or by a smart contract that forwards ETH — is permanently frozen. There is no on-chain path to recover it. This constitutes permanent loss/freezing of user funds.

### Likelihood Explanation
The `OmniBridge` contract is a well-known, publicly deployed bridge contract. Users and integrators routinely send ETH directly to contract addresses when attempting to bridge native ETH. The `receive()` function silently accepts the ETH without reverting, giving no indication that the funds are lost. The likelihood of accidental ETH being sent and permanently locked is realistic and has precedent across many bridge deployments.

### Recommendation
Either remove the `receive()` function entirely (ETH bridging is already handled by the `payable initTransfer()` function), or restrict it to only accept ETH from a known, trusted source (e.g., a WETH contract during an unwrap step). Additionally, add an admin-only ETH rescue function as a safety net:

```solidity
// Option 1: Remove receive() entirely — initTransfer is already payable

// Option 2: Restrict the sender
receive() external payable {
    if (msg.sender != address(weth)) revert UnauthorizedETHSender();
}

// Option 3: Add an admin rescue function
function rescueETH(address payable to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
    (bool success, ) = to.call{value: amount}("");
    if (!success) revert FailedToSendEther();
}
```

### Proof of Concept
1. Deploy `OmniBridge` (or `OmniBridgeWormhole`) on a testnet.
2. Send ETH directly to the contract address with no calldata (triggering `receive()`).
3. Observe that `address(bridge).balance` increases.
4. Attempt to recover the ETH — no function exists to do so.
5. The ETH is permanently locked; `finTransfer` cannot release it because no corresponding `InitTransfer` event or nonce was ever recorded for this ETH. [4](#0-3) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-322)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-413)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-596)
```text
    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }

    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }

    function upgradeToken(
        address tokenAddress,
        address implementation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(isBridgeToken[tokenAddress], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken proxy = BridgeToken(tokenAddress);
        proxy.upgradeToAndCall(implementation, bytes(""));
    }

    function setNearBridgeDerivedAddress(
        address nearBridgeDerivedAddress_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    }

    receive() external payable {}

    function deriveDeterministicAddress(
        address tokenAddress,
        uint256 tokenId
    ) public pure returns (address) {
        return
            address(
                bytes20(keccak256(abi.encodePacked(tokenAddress, tokenId)))
            );
    }

    function _normalizeDecimals(uint8 decimals) internal pure returns (uint8) {
        uint8 maxAllowedDecimals = 18;
        if (decimals > maxAllowedDecimals) {
            return maxAllowedDecimals;
        }
        return decimals;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
```
