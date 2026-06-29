### Title
Native ETH Delivery to Non-Payable Contract Recipient Permanently Freezes Bridged Funds — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge::finTransfer` delivers native ETH to `payload.recipient` via a low-level call. If the recipient is a contract without a `receive()` or `payable fallback()` function, the call fails and the entire transaction reverts. Because the NEAR-side tokens are already burned/locked and the MPC signature is cryptographically bound to that recipient address, the transfer can never be finalized, permanently freezing the user's bridged funds with no on-chain recovery path.

### Finding Description
In `OmniBridge::finTransfer`, when `payload.tokenAddress == address(0)` (native ETH bridging), the contract attempts to push ETH to the recipient:

```solidity
if (payload.tokenAddress == address(0)) {
    // slither-disable-next-line arbitrary-send-eth
    (bool success, ) = payload.recipient.call{value: payload.amount}(
        ""
    );
    if (!success) revert FailedToSendEther();
}
``` [1](#0-0) 

If `payload.recipient` is a contract that does not implement `receive()` or a `payable fallback()`, the call returns `success = false` and the function reverts with `FailedToSendEther`. Because the entire transaction reverts, the `completedTransfers[payload.destinationNonce] = true` state write is also rolled back:

```solidity
completedTransfers[payload.destinationNonce] = true;
``` [2](#0-1) 

The nonce is therefore never consumed. Every subsequent relay attempt produces the same revert. The NEAR-side tokens, however, were already burned or locked at `init_transfer` time and there is no cancel/refund function in the NEAR bridge contract that would allow the user to recover them.

The `OmniBridge` contract itself has a `receive()` function, so it can hold ETH: [3](#0-2) 

This confirms native ETH bridging is an intended, supported path — not a hypothetical one.

### Impact Explanation
A user who specifies a non-payable contract address as the EVM recipient when initiating a native ETH transfer from NEAR will have their tokens permanently frozen:
- Tokens are burned/locked on NEAR at `init_transfer` time.
- The MPC signature covers the recipient address; no re-signing to a different recipient is possible.
- `finTransfer` reverts on every relay attempt.
- No NEAR-side cancellation or refund mechanism exists.

This constitutes **permanent freezing of bridged funds**, which is within the critical impact scope.

### Likelihood Explanation
Medium. Users commonly specify smart contract addresses as recipients — multisig wallets (e.g., Gnosis Safe), DAO treasuries, DeFi protocol vaults, or custom receiver contracts — many of which do not implement `receive()`. A single mistaken recipient address results in an irrecoverable loss. The `OmniBridgeWormhole` variant (used on Arbitrum, Base, Polygon, BNB) inherits the same `finTransfer` and is equally affected. [4](#0-3) 

### Recommendation
Replace the push-payment pattern with a pull-payment (escrow) pattern for native ETH delivery: store the ETH in the contract mapped to the recipient's address and emit an event, then let the recipient (or any caller on their behalf) withdraw. This eliminates the dependency on the recipient's ability to accept ETH in the same transaction and prevents permanent fund freezing.

### Proof of Concept
1. Alice holds 1 ETH worth of a NEAR-native token and initiates a transfer to EVM, specifying `recipient = address(MyDaoTreasury)` — a contract with no `receive()`.
2. The NEAR bridge burns Alice's tokens and the MPC network signs the `TransferMessagePayload` with `tokenAddress = address(0)`, `amount = 1 ETH`, `recipient = address(MyDaoTreasury)`.
3. A relayer calls `OmniBridge.finTransfer(signature, payload)` on EVM.
4. `completedTransfers[nonce] = true` is written, then `MyDaoTreasury.call{value: 1 ether}("")` returns `success = false`.
5. `revert FailedToSendEther()` rolls back the entire transaction, including the nonce write.
6. Every subsequent relay attempt produces the same revert.
7. Alice's tokens are permanently burned on NEAR; the 1 ETH remains locked in the bridge contract forever.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L287-287)
```text
        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L574-574)
```text
    receive() external payable {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L26-46)
```text
contract OmniBridgeWormhole is OmniBridge {
    IWormhole private _wormhole;
    // https://wormhole.com/docs/build/reference/consistency-levels
    uint8 private _consistencyLevel;
    uint32 public wormholeNonce;

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
