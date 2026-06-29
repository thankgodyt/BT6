### Title
No Token/ETH Recovery Function in OmniBridge Contract — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.sol` explicitly accepts ETH via `receive() external payable {}` and accumulates ERC-20 tokens through its `initTransfer` escrow path, but contains no `sweep()` or admin-callable recovery function. ETH or tokens that arrive outside the normal bridge accounting (accidental sends, airdrops, returned tokens) are permanently frozen with no on-chain recovery path.

### Finding Description
`OmniBridge` declares an unconditional ETH receiver:

```solidity
receive() external payable {}
``` [1](#0-0) 

During `initTransfer` for ERC-20 tokens, the contract pulls tokens directly into itself:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount
);
``` [2](#0-1) 

Additionally, every `initTransfer` call (both ETH and ERC-20 paths) accepts a `nativeFee` component in `msg.value`. For ERC-20 transfers, `extensionValue = msg.value - nativeFee`, meaning the `nativeFee` ETH is retained in the contract and only `extensionValue` is forwarded to Wormhole:

```solidity
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);
``` [3](#0-2) 

A full search of all `.sol` files under `evm/src/` confirms there is no `sweep`, `withdrawETH`, `rescueTokens`, or equivalent admin-callable recovery function anywhere in the contract hierarchy (`OmniBridge`, `OmniBridgeWormhole`, `BridgeToken`, `SelectivePausableUpgradable`). [4](#0-3) 

### Impact Explanation
Any ETH or ERC-20 tokens that arrive in the contract outside the normal bridge accounting are permanently frozen:

- **Accidental ETH sends** via `receive()` — no accounting entry, no recovery path.
- **Airdropped ERC-20 tokens** sent directly to the contract address — permanently stuck.
- **Returned tokens** — a recipient who recognises a mistake and sends tokens back to the contract address loses them permanently.
- **Accumulated `nativeFee` ETH** from ERC-20 `initTransfer` calls — this ETH is retained in the contract but is indistinguishable from bridge ETH escrow; if the ETH bridge direction has no outbound demand, it accumulates with no recovery path.

Because `finTransfer` only releases exact amounts specified in MPC-signed payloads, the surplus funds can never be released through normal bridge operation. The result is permanent, irrecoverable loss of funds held in the bridge contract.

### Likelihood Explanation
The `receive()` function is public and unconditional. Airdrops to high-value bridge contract addresses are common in practice. Token senders making mistakes and returning funds to the contract address is a realistic scenario. The `nativeFee` ETH accumulation happens on every ERC-20 `initTransfer` call that includes a non-zero `nativeFee`. All of these are reachable by any unprivileged external actor without any special access.

### Recommendation
Add an admin-only `sweep` function to recover ETH and arbitrary ERC-20 tokens that are not part of the bridge's tracked escrow:

```solidity
function sweep(address token, address to, uint256 amount)
    external
    onlyRole(DEFAULT_ADMIN_ROLE)
{
    if (token == address(0)) {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "ETH transfer failed");
    } else {
        IERC20(token).safeTransfer(to, amount);
    }
}
```

The `to` address should be a protocol-controlled multisig or treasury. For the Wormhole variant, the function should account for the fact that some ETH is legitimate bridge escrow (ETH locked for NEAR→EVM payouts) and only sweep the surplus.

### Proof of Concept

1. Deploy `OmniBridgeWormhole` on a testnet.
2. Call `initTransfer(erc20Token, 1e18, 0, 1e16, "recipient.near", "")` with `msg.value = 1e16` (the `nativeFee`). The `nativeFee` ETH is retained in the contract; `extensionValue = 0` is forwarded to Wormhole.
3. Separately, send 1 ETH directly to the contract address — accepted silently by `receive()`.
4. Airdrop any ERC-20 token directly to the contract address.
5. Attempt to recover any of these funds — no function exists to do so. The ETH and tokens are permanently frozen. [5](#0-4) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L386-413)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-599)
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

    uint256[49] private __gap;
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
