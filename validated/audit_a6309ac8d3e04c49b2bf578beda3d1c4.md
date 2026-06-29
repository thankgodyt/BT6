The code confirms the claim. Let me verify the key facts:

1. `completedTransfers[payload.destinationNonce] = true` is set at line 287, **before** the ETH transfer at lines 319–322.
2. If `payload.recipient.call{value: payload.amount}("")` returns `success = false`, `revert FailedToSendEther()` is triggered, rolling back **all** state changes including the nonce marking.
3. The nonce is therefore never consumed, and every retry fails identically.
4. The `evm/SECURITY.md` does not list this as a known/accepted issue.
5. The recipient is encoded in the MPC-signed `TransferMessagePayload` and is immutable post-signing.

---

Audit Report

## Title
Native ETH Delivery to ETH-Rejecting Recipient Permanently Freezes Bridged Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
In `OmniBridge.finTransfer`, native ETH is delivered to `payload.recipient` via a bare low-level call. If the recipient is a contract that reverts on ETH receipt, the call fails, `revert FailedToSendEther()` rolls back all state including the nonce marking, and the transfer can never be finalized. Because the recipient is fixed in the MPC-signed payload and no fallback or recovery path exists, the user's funds locked on NEAR are permanently frozen.

## Finding Description
In `finTransfer` (OmniBridge.sol L279–367), the nonce is marked consumed at L287 (`completedTransfers[payload.destinationNonce] = true`) before any token delivery. For native ETH (`payload.tokenAddress == address(0)`), delivery is attempted at L319–322:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();
```

If `payload.recipient` is a contract with no `receive`/`fallback`, or one that explicitly reverts, `success` is `false` and `revert FailedToSendEther()` fires. Solidity reverts roll back all state changes in the transaction, including the L287 nonce assignment. The nonce is therefore never durably consumed. Every subsequent relay attempt reaches the same ETH send, fails identically, and reverts again. The `TransferMessagePayload.recipient` field is embedded in the Borsh-encoded message that is verified against the MPC-derived `nearBridgeDerivedAddress` signature (L311–313); it cannot be altered post-signing. No admin function exists to redirect or recover a stuck ETH transfer.

## Impact Explanation
This directly causes **permanent freezing of bridged native ETH funds**: the user's ETH equivalent is locked/burned on NEAR at `initTransfer` time, and `finTransfer` on the EVM side can never succeed. This matches the Critical allowed impact: *"permanent freezing of bridged funds across NEAR, EVM."* The loss is irreversible with no on-chain recovery path.

## Likelihood Explanation
Any bridge user can trigger this, accidentally or deliberately. Accidental cases include bridging ETH to a multisig, DAO treasury, or smart contract wallet that lacks a `receive` function — a common real-world scenario. Deliberate cases require only deploying a one-line ETH-rejecting contract and using its address as the EVM recipient. No special privileges, admin access, or external dependencies are required.

## Recommendation
Replace the bare ETH call with a try-WETH fallback:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) {
    IWETH(weth).deposit{value: payload.amount}();
    IERC20(weth).safeTransfer(payload.recipient, payload.amount);
}
```

Alternatively, detect contract recipients via `payload.recipient.code.length > 0` and always deliver WETH to them. Either approach eliminates the revert path and ensures the nonce is always durably consumed on first execution.

## Proof of Concept
1. Deploy on the EVM destination chain:
   ```solidity
   contract EthRejecter {
       receive() external payable { revert("NO ETH"); }
   }
   ```
2. On NEAR, call `initTransfer` for a native ETH bridge transfer specifying `address(ethRejecter)` as the EVM recipient. NEAR locks/burns the user's funds and the MPC produces a signed `TransferMessagePayload`.
3. Call `OmniBridge.finTransfer(signatureData, payload)`. Execution reaches L319; `EthRejecter.receive()` reverts; `finTransfer` reverts with `FailedToSendEther()`. The L287 nonce assignment is rolled back.
4. Confirm `completedTransfers[payload.destinationNonce] == false` after the failed call.
5. Repeat step 3 any number of times — each attempt fails identically. The user's funds are permanently frozen with no recovery path.