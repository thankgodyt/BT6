### Title
Native ETH Delivery Failure in `finTransfer` Permanently Freezes Bridged Funds - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
When `finTransfer` is called to deliver native ETH (`tokenAddress == address(0)`) to a smart-contract recipient that reverts on ETH receipt, the entire transaction reverts. Because the revert also undoes the `completedTransfers[destinationNonce] = true` write, the nonce is never consumed. The recipient address is immutably embedded in the MPC-signed payload, so no retry can ever succeed. The user's funds are permanently frozen on the source chain with no recovery path.

### Finding Description
`finTransfer` in `OmniBridge.sol` marks the destination nonce as used **before** attempting the ETH delivery:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287
```

Then, for native ETH transfers, it performs:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();              // line 322
``` [1](#0-0) 

If `payload.recipient` is a smart contract that has no `receive()` / `fallback()` function, or whose `receive()` reverts, the low-level `call` returns `success = false`. The function then reverts with `FailedToSendEther()`. Because Solidity reverts roll back **all** state changes in the transaction, the `completedTransfers[destinationNonce] = true` write at line 287 is also rolled back — the nonce is never consumed.

The recipient address is part of the Borsh-encoded payload that was signed by the NEAR MPC signer:

```solidity
Borsh.encodeAddress(payload.recipient),   // line 298
``` [2](#0-1) 

Changing `payload.recipient` invalidates the signature. There is no admin override, no alternative-recipient claim function, and no mechanism to mark the nonce as used without delivering the ETH. Every future call to `finTransfer` with the same valid payload will hit the same revert. The contract holds no ETH for the user; the locked/burned tokens on the source chain are irrecoverable.

### Impact Explanation
Permanent freezing of bridged native ETH. Any user who initiates a NEAR → EVM transfer of native ETH and specifies a smart-contract address as the recipient (e.g., a multisig, a DeFi vault, a proxy without a payable fallback) will have their funds locked on the source chain forever. There is no admin escape hatch and no way to re-route the delivery.

### Likelihood Explanation
Smart-contract recipients are a normal use case for a bridge (DeFi integrations, multisigs, protocol treasuries). The `message` field in the transfer payload already anticipates programmatic recipients. Any such recipient that does not implement a payable `receive()` triggers the freeze. The user need only initiate one transfer to a non-payable contract address to lose their funds permanently.

### Recommendation
Apply the pull-over-push pattern for native ETH delivery: instead of reverting on a failed `call`, record the unclaimed amount in a mapping keyed by `(destinationNonce, recipient)` and mark the nonce as used. Expose a separate `claimEth(uint64 destinationNonce)` function that lets the recipient (or an admin-designated fallback address) withdraw the ETH. This eliminates the permanent-freeze scenario while preserving replay protection.

Alternatively, if the intent is to support only EOA recipients for native ETH, enforce this with `require(payload.recipient.code.length == 0, "ETH recipient must be EOA")` before the transfer, so the failure is caught at initiation time on the source chain rather than silently freezing funds after the cross-chain proof is submitted.

### Proof of Concept

1. **Source chain**: User calls `initTransfer` on NEAR (or any supported chain) with `tokenAddress = address(0)` and `recipient = <address of a contract with no receive()>`.
2. **MPC signing**: The NEAR MPC network signs the `TransferMessage` payload, embedding the non-payable contract address as `recipient`.
3. **Finalization attempt**: A relayer calls `OmniBridge.finTransfer(signatureData, payload)` on the EVM chain.
4. **Revert**: `payload.recipient.call{value: payload.amount}("")` returns `success = false`; the function reverts with `FailedToSendEther()`. The `completedTransfers[destinationNonce]` write is rolled back.
5. **Stuck state**: Every subsequent `finTransfer` call with the same valid payload hits the same revert. No other function can consume the nonce or release the ETH. The user's source-chain tokens are permanently locked/burned. [3](#0-2) [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L44-44)
```text
    mapping(uint64 => bool) public completedTransfers;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-322)
```text
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
