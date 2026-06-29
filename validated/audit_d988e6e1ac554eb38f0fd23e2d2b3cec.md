### Title
Unvalidated `msg.value` in `finTransfer` Permanently Locks Caller ETH for Non-Native Token Transfers — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.finTransfer` is declared `payable` but contains no check that `msg.value == 0` when the payload describes a non-native-ETH token transfer (`payload.tokenAddress != address(0)`). Any ETH attached to such a call is silently accepted by the contract and permanently locked, because the contract has no ETH-recovery or withdrawal function.

---

### Finding Description

`finTransfer` in `OmniBridge.sol` is the public entry point through which any relayer (or any external caller) finalises an inbound cross-chain transfer on the EVM side. [1](#0-0) 

The function is `external payable`. Inside, it branches on `payload.tokenAddress`:

- `address(0)` → sends `payload.amount` of ETH from the **contract's own balance** to the recipient. `msg.value` is not consumed here; it merely adds to the contract's ETH balance.
- Any other address → mints or transfers an ERC-20 / ERC-1155 / custom-minter token. `msg.value` is **completely ignored**. [2](#0-1) 

There is no `require(msg.value == 0, ...)` guard before the ERC-20 branch, and there is no ETH-refund path. The contract does have a bare `receive()`: [3](#0-2) 

…but no `withdraw`, `rescueEth`, or equivalent admin function exists anywhere in the contract. ETH sent to `finTransfer` for a non-ETH token transfer is therefore permanently locked.

The same structural issue exists in `logMetadata` and `logMetadata1155`, which are also `payable` while their extension hook (`logMetadataExtension`) is a no-op in the base contract: [4](#0-3) [5](#0-4) 

`finTransfer` is the highest-severity instance because it is the primary relayer-facing function and the amounts involved can be large.

---

### Impact Explanation

Any ETH attached to a `finTransfer` call for an ERC-20 (or ERC-1155, bridge token, or custom-minter) transfer is irrecoverably locked inside `OmniBridge`. There is no admin withdrawal path. The loss is permanent and proportional to `msg.value` supplied by the caller. This constitutes a direct, permanent loss of user/relayer funds.

---

### Likelihood Explanation

`finTransfer` is called by relayers and, in permissionless configurations, by any bridge user. The function signature is `payable`, so standard tooling does not warn callers against attaching ETH. A relayer that also handles native-ETH transfers on the same contract may inadvertently reuse a call template that includes `value`, or a user may attach ETH believing it covers a gas subsidy or Wormhole fee. The mistake is easy to make and undetectable until funds are already lost.

---

### Recommendation

Add an explicit guard at the top of `finTransfer` (and `logMetadata` / `logMetadata1155`) for the non-ETH-token path:

```solidity
// In finTransfer, before the token-dispatch block:
if (payload.tokenAddress != address(0)) {
    require(msg.value == 0, "OB: wrong msg.value");
}
```

Alternatively, remove the `payable` modifier from `finTransfer` entirely and introduce a separate `depositEth()` function for pre-funding the contract's native-ETH reserve, making the two concerns explicit and impossible to confuse.

---

### Proof of Concept

1. Deploy `OmniBridge` (or use the live proxy).
2. A valid MPC-signed payload exists for an ERC-20 token transfer (e.g., a wrapped NEAR token, `payload.tokenAddress != address(0)`).
3. Call `finTransfer(signatureData, payload)` with `{value: 1 ether}`.
4. The signature check passes; the ERC-20 is minted/transferred to `payload.recipient`.
5. The 1 ETH is now held by `OmniBridge` with no mechanism to retrieve it.
6. Confirm: `address(omniBridge).balance` increased by 1 ETH; no withdrawal function exists. [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L272-277)
```text
    function logMetadataExtension(
        address tokenAddress,
        string memory name,
        string memory symbol,
        uint8 decimals
    ) internal virtual {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-282)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-355)
```text
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
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L574-574)
```text
    receive() external payable {}
```
