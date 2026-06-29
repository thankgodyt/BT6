Audit Report

## Title
Native ETH Transfer to Non-Payable Contract Recipient Permanently Freezes Bridged Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
In `OmniBridge.finTransfer`, the destination nonce is marked used at line 287 before the ETH transfer attempt at lines 319–322. When the recipient is a contract without a `receive()` or `fallback()` function, `revert FailedToSendEther()` rolls back the entire transaction — including the nonce write — leaving the nonce unconsumed. Because the MPC signature binds the recipient address, no relay attempt can ever succeed, permanently freezing the ETH inside the bridge while the corresponding NEAR-side burn is already finalized.

## Finding Description
`finTransfer` executes in this order:

1. **Line 287**: `completedTransfers[payload.destinationNonce] = true` — nonce marked used.
2. **Lines 289–313**: Borsh-encode the payload and verify the MPC signature. The recipient address is embedded in the signed message, making it immutable.
3. **Lines 317–322**: For native ETH (`payload.tokenAddress == address(0)`), attempt delivery via `payload.recipient.call{value: payload.amount}("")`. If the call returns `success = false`, `revert FailedToSendEther()` is raised.

The `revert` at line 322 unwinds **all** state changes in the transaction, including the nonce write at line 287. The nonce therefore remains unconsumed. On every subsequent relay attempt the nonce check at line 283 passes, signature verification passes, and execution reaches the same failing `call` — producing the same revert indefinitely. There is no admin escape hatch, escrow fallback, or protocol-level refund path. The ETH accumulates in the bridge (which has a bare `receive()` at line 574) with no mechanism to release it to the intended recipient or return it to the sender.

## Impact Explanation
The user's NEAR tokens are irreversibly burned or locked on the NEAR side. The corresponding ETH held by the bridge contract can never be delivered and cannot be recovered through any protocol-defined path. This constitutes **permanent freezing of bridged funds**, matching the Critical impact class: *"permanent freezing of bridged funds across NEAR, EVM … flows."*

## Likelihood Explanation
No attacker capability is required; the condition is triggered by any unprivileged user who specifies a non-payable contract as the EVM recipient for a native-ETH bridge transfer. This is a routine scenario: Gnosis Safe multisigs, DAO treasuries, protocol vaults, and many smart-contract wallets do not implement `receive()`. The condition can be reached accidentally, requires no special knowledge, and is repeatable across any such recipient address.

## Recommendation
Replace the push-payment pattern with a pull-payment (escrow) model: credit `claimable[payload.recipient] += payload.amount` and expose a separate `claimETH()` function. Alternatively, wrap the `call` in a try/catch-style pattern — if delivery fails, hold the ETH in a per-recipient escrow mapping so the recipient (or an admin recovery path) can withdraw it later. This prevents any failed delivery from permanently locking funds.

## Proof of Concept
1. Deploy a contract `NoReceive` with no `receive()` or `fallback()` on a local fork.
2. On the NEAR side, initiate a native-ETH bridge transfer specifying `NoReceive`'s address as the EVM recipient; the NEAR-side burn finalizes.
3. The MPC service signs a `TransferMessagePayload` embedding `NoReceive`'s address.
4. Call `OmniBridge.finTransfer(signatureData, payload)` with the signed payload.
5. Execution reaches line 319: `NoReceive.call{value: amount}("")` returns `(false, "")`.
6. Line 322 reverts with `FailedToSendEther()`; `completedTransfers[nonce]` remains `false`.
7. Repeat step 4 — identical revert every time.
8. Confirm: `completedTransfers[nonce] == false`, bridge ETH balance unchanged, NEAR tokens gone.