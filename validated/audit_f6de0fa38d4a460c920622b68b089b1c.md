### Title
`nativeFee` ETH Permanently Locked With No Withdrawal Mechanism — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol` accepts native ETH via `initTransfer` (as `nativeFee`) and via an unconditional `receive()` fallback, but contains no function to withdraw accumulated native ETH. Every `initTransfer` call with a non-zero `nativeFee` permanently locks that ETH in the contract.

---

### Finding Description

In `OmniBridge.initTransfer`, the caller supplies `msg.value` covering three components: the Wormhole relay fee (`extensionValue`), the bridged `amount` (for native-ETH transfers), and `nativeFee`. Only `extensionValue` is forwarded — to Wormhole via `initTransferExtension` — while `nativeFee` is silently retained by the contract: [1](#0-0) 

For ERC-20 transfers: `extensionValue = msg.value - nativeFee`, so `nativeFee` stays in the contract.
For native-ETH transfers: `extensionValue = msg.value - amount - nativeFee`, so both `amount` (held for the recipient) and `nativeFee` stay in the contract.

`OmniBridgeWormhole.initTransferExtension` confirms only `value` (i.e., `extensionValue`) is forwarded to Wormhole: [2](#0-1) 

Additionally, the contract exposes an unconditional payable fallback: [3](#0-2) 

Searching the entire `OmniBridge.sol` reveals **no `withdraw` function, no `rescueEth`, and no admin-callable ETH-transfer path** for native ETH. The only ETH egress is the `finTransfer` path that sends `payload.amount` to a recipient for native-ETH inbound transfers: [4](#0-3) 

That path is gated on a valid MPC signature and a specific `tokenAddress == address(0)` payload — it cannot be used to recover accumulated `nativeFee` balances.

---

### Impact Explanation

Every `initTransfer` call with `nativeFee > 0` permanently locks that ETH in the contract. The `nativeFee` is the mechanism by which users compensate relayers for cross-chain message delivery; it is never distributed to relayers or the protocol, and it cannot be recovered by any party. Over time, the locked balance grows proportionally to bridge usage. This constitutes permanent freezing of user-paid funds with no recovery path short of a contract upgrade.

---

### Likelihood Explanation

`initTransfer` is the primary user-facing entry point for every outbound EVM→NEAR transfer. Any user who sets `nativeFee > 0` (which is the normal operating mode when a relayer is expected to be compensated) contributes to the locked balance. No special attacker role is required — any bridge user triggers this on every transfer.

---

### Recommendation

Add an admin-restricted withdrawal function for accumulated native ETH, analogous to the provider `withdraw` in the referenced Entropy contract. For example:

```solidity
function withdrawNativeFees(address payable recipient, uint256 amount)
    external onlyRole(DEFAULT_ADMIN_ROLE)
{
    (bool ok, ) = recipient.call{value: amount}("");
    require(ok, "transfer failed");
}
```

Also consider whether `nativeFee` should be forwarded directly to a designated fee recipient at `initTransfer` time rather than held by the contract.

---

### Proof of Concept

1. Alice calls `OmniBridge.initTransfer(tokenAddress=USDC, amount=1000e6, fee=0, nativeFee=0.01 ether, recipient="alice.near", message="")` sending `msg.value = 0.01 ether + wormholeFee`.
2. Inside `initTransfer`: `extensionValue = msg.value - nativeFee = wormholeFee`. The `0.01 ether` `nativeFee` remains in the contract.
3. `initTransferExtension` forwards only `wormholeFee` to Wormhole.
4. After 10,000 such transfers at `nativeFee = 0.01 ether`, 100 ETH is locked in the contract.
5. No admin function, no user function, and no protocol path exists to recover this ETH. The funds are permanently frozen. [5](#0-4)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-426)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L574-574)
```text
    receive() external payable {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L143-147)
```text
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );
```
