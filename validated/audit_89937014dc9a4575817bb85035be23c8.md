### Title
Malicious or Non-Payable Recipient Contract Can Permanently Freeze Bridged ETH via Push Transfer in `finTransfer` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`finTransfer` delivers native ETH to the recipient via a push `.call{value:}` pattern. If the recipient is a contract whose `receive`/fallback function reverts, the entire `finTransfer` call reverts. Because the source-chain funds are already burned/locked on NEAR before `finTransfer` is ever called, and because no retry with a different recipient is possible (the payload is MPC-signed and fixed), the bridged ETH is permanently frozen with no recovery path.

---

### Finding Description

In `OmniBridge.sol`, `finTransfer` handles native ETH delivery at lines 317–322:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [1](#0-0) 

The nonce is marked consumed at line 287 before the transfer executes:

```solidity
completedTransfers[payload.destinationNonce] = true;
``` [2](#0-1) 

If the `.call` reverts (because `payload.recipient` is a contract with a reverting `receive()`), the entire transaction reverts — including the nonce assignment. The nonce is therefore never consumed, and the relayer can retry. However, every retry hits the same reverting recipient, so the transfer can **never** be finalized. The NEAR-side burn/lock is already committed and irreversible. The result is permanent fund freeze.

The same push-transfer risk applies to the ERC-1155 branch at lines 323–330, where `safeTransferFrom` invokes `onERC1155Received` on the recipient contract — a revert there has identical consequences. [3](#0-2) 

---

### Impact Explanation

Permanent freezing of bridged funds. Once a NEAR → EVM transfer is initiated, the NEAR-side tokens are burned. If the designated EVM recipient is a contract that reverts on ETH receipt, `finTransfer` can never succeed for that transfer. The funds are destroyed on NEAR and undeliverable on EVM, with no protocol-level recovery mechanism.

---

### Likelihood Explanation

Medium. Users routinely bridge to smart contract addresses — multisigs, DeFi vaults, DAOs — many of which do not implement a payable `receive()`. A user who bridges native ETH to such an address loses their funds permanently. Additionally, a malicious actor can intentionally deploy a reverting contract as recipient before initiating the transfer, demonstrating the path is fully attacker-controlled and requires no privileged access.

---

### Recommendation

Replace the push pattern with a pull pattern: on successful signature verification, store the ETH amount in a `pendingWithdrawals[recipient]` mapping and emit an event. Let the recipient call a separate `claimNative()` function to withdraw. This decouples finalization success from recipient behavior and eliminates the permanent-freeze risk.

---

### Proof of Concept

1. Deploy `MaliciousRecipient` on EVM with `receive() external payable { revert(); }`.
2. Initiate a NEAR → EVM transfer of native ETH, specifying `MaliciousRecipient` as the EVM recipient. NEAR burns the tokens.
3. Relayer obtains the MPC-signed `TransferMessagePayload` and calls `finTransfer`.
4. Execution reaches line 319: `payload.recipient.call{value: payload.amount}("")` triggers `MaliciousRecipient.receive()`, which reverts.
5. `finTransfer` reverts with `FailedToSendEther`. The nonce assignment at line 287 is also rolled back.
6. Every subsequent relay attempt with the same (fixed, MPC-signed) payload hits the same revert.
7. The NEAR-side burn is final. The ETH is permanently frozen — unclaimable on EVM, unrecoverable on NEAR. [4](#0-3)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L323-330)
```text
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
```
