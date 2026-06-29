### Title
`nativeFee` ETH Permanently Locked in `OmniBridge` — No Withdrawal Mechanism - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `initTransfer` and `initTransfer1155` functions in `OmniBridge.sol` are `payable` and accept ETH from callers as `nativeFee`. This ETH is retained in `address(this)` but the contract exposes no function to withdraw or forward it to any relayer or admin. Every call with `nativeFee > 0` permanently locks that ETH in the contract.

---

### Finding Description

`initTransfer` computes `extensionValue = msg.value - nativeFee` for ERC-20 token transfers, and `extensionValue = msg.value - amount - nativeFee` for native ETH transfers. The `extensionValue` portion is either forwarded to Wormhole (in `OmniBridgeWormhole`) or must be zero (in the base `OmniBridge`, which reverts on `value != 0`). In both cases, the `nativeFee` portion of `msg.value` is never forwarded — it stays in the contract. [1](#0-0) 

The `nativeFee` is emitted in the `InitTransfer` event as a signal to the relayer of how much fee they should receive, but the actual ETH is never sent to the relayer on the EVM side. [2](#0-1) 

`initTransfer1155` has the same pattern: [3](#0-2) 

A full audit of all functions in `OmniBridge.sol` confirms there is no `withdraw`, `rescueETH`, or any admin function that moves ETH out of the contract. The only ETH egress is `finTransfer` sending `payload.amount` to a recipient when `tokenAddress == address(0)`, which is for bridging native ETH — not for reclaiming `nativeFee`. [4](#0-3) 

The contract also has a bare `receive()` fallback, confirming it is designed to hold ETH, but no corresponding egress for `nativeFee` balances: [5](#0-4) 

---

### Impact Explanation

Every bridge user who calls `initTransfer` or `initTransfer1155` with `nativeFee > 0` permanently loses that ETH. The funds accumulate in the contract and are irrecoverable — no admin, relayer, or user can retrieve them. This is a direct permanent freezing of user funds on the EVM side of the bridge, matching the "permanent freezing of bridged funds" impact class.

---

### Likelihood Explanation

High. The `nativeFee` parameter is a documented, first-class feature of the EVM API (shown in the README as a required parameter of `initTransfer`). Any user following the documented bridge flow who sets a non-zero `nativeFee` to incentivize a relayer will have that ETH permanently locked. This occurs during normal, intended operation of the bridge. [6](#0-5) 

---

### Recommendation

Add a mechanism to forward or withdraw the `nativeFee` ETH. Two options:

**Option A** — Forward `nativeFee` directly to a designated relayer fee recipient at call time:
```solidity
if (nativeFee > 0) {
    (bool ok, ) = feeRecipient.call{value: nativeFee}("");
    require(ok, "NativeFee transfer failed");
}
```

**Option B** — Add an admin rescue function:
```solidity
function withdrawNativeFees(address payable recipient, uint256 amount)
    external onlyRole(DEFAULT_ADMIN_ROLE)
{
    (bool ok, ) = recipient.call{value: amount}("");
    require(ok, "Withdraw failed");
}
```

Option A is preferred as it ensures relayers are compensated atomically and avoids accumulation.

---

### Proof of Concept

1. User calls `initTransfer(tokenAddress, amount, fee, 1 ether, "recipient.near", "")` with `msg.value = 1 ether`.
2. `extensionValue = 1 ether - 1 ether = 0`. Base `OmniBridge` does not revert.
3. `initTransferExtension` is called with `value = 0` — no ETH is forwarded anywhere.
4. `InitTransfer` event is emitted with `nativeFee = 1 ether`.
5. `address(OmniBridge).balance` increases by `1 ether`.
6. No function exists to retrieve this ETH. It is permanently locked. [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-380)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-436)
```text
        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L466-478)
```text
        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L492-506)
```text
    function initTransferExtension(
        address /*sender*/,
        address /*tokenAddress*/,
        uint64 /*originNonce*/,
        uint128 /*amount*/,
        uint128 /*fee*/,
        uint128 /*nativeFee*/,
        string calldata /*recipient*/,
        string calldata /*message*/,
        uint256 value
    ) internal virtual {
        if (value != 0) {
            revert InvalidValue();
        }
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L574-574)
```text
    receive() external payable {}
```
