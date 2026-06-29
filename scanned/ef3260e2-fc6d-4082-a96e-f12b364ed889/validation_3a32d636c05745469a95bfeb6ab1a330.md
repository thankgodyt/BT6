### Title
`OmniBridge` accumulates `nativeFee` ETH with no withdrawal path — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.sol` has a bare `receive()` function and collects a `nativeFee` component from every `initTransfer` / `initTransfer1155` call. Neither the `nativeFee` ETH nor any ETH sent directly to the contract can ever leave: there is no ETH-withdrawal function anywhere in the contract or its Wormhole extension.

### Finding Description
`OmniBridge` exposes a bare `receive()` at line 574, making the contract unconditionally accept ETH: [1](#0-0) 

Every `initTransfer` call requires the caller to supply `msg.value` covering `amount + nativeFee` (for native-ETH transfers) or `nativeFee` alone (for ERC-20 transfers). The code splits `msg.value` into `extensionValue` (forwarded to Wormhole or another extension) and `nativeFee`, which is simply left in the contract: [2](#0-1) 

In `OmniBridgeWormhole`, only `extensionValue` (= `msg.value − nativeFee`) is forwarded to the Wormhole core contract: [3](#0-2) 

A repository-wide search for `withdraw`, `rescueEth`, `rescueETH`, and `emergencyWithdraw` across all EVM Solidity files returns zero matches. There is no function that can move accumulated ETH out of `OmniBridge`.

### Impact Explanation
Every `initTransfer` call that passes a non-zero `nativeFee` permanently locks that ETH in the contract. Over the lifetime of the bridge this accumulates into a growing pool of irrecoverable protocol fees. This is fee mis-accounting that permanently changes protocol balances — fitting the Critical allowed-impact category ("fee mis-accounting … that changes user or protocol balances").

### Likelihood Explanation
`nativeFee` is a first-class parameter of the public `initTransfer` interface and is expected to be non-zero whenever a relayer fee is required. Every ordinary bridge user who pays a relayer fee triggers the accumulation. Likelihood is high.

### Recommendation
Add an admin-gated ETH-rescue function to `OmniBridge`, for example:

```solidity
function rescueEth(address payable to, uint256 amount)
    external
    onlyRole(DEFAULT_ADMIN_ROLE)
{
    (bool ok, ) = to.call{value: amount}("");
    if (!ok) revert FailedToSendEther();
}
```

This mirrors the recommendation in the original `HibernationDen` report and ensures that LayerZero/Wormhole refunds and accumulated `nativeFee` ETH can be recovered.

### Proof of Concept

1. Deploy `OmniBridgeWormhole` (or the base `OmniBridge`).
2. Call `initTransfer` with any ERC-20 token, `nativeFee = 1 ether`, sending `msg.value = 1 ether`.
   - `extensionValue = msg.value − nativeFee = 0` → Wormhole receives 0 ETH.
   - `nativeFee = 1 ether` remains in the contract.
3. Repeat for N users; the contract balance grows by `N × nativeFee`.
4. Attempt any call to recover the ETH — no such function exists.
5. The ETH is permanently locked. [4](#0-3) [1](#0-0)

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L574-574)
```text
    receive() external payable {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L141-148)
```text
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

```
