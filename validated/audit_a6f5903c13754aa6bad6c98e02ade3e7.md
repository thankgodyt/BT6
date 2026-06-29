Audit Report

## Title
Native ETH delivery failure in `finTransfer` permanently freezes bridged funds when recipient cannot receive ETH - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
In `finTransfer`, when `payload.tokenAddress == address(0)`, ETH is pushed to `payload.recipient` via a low-level `.call`. If the recipient is a contract without a `receive()` or `fallback()` function, the call fails and the entire transaction reverts — including the nonce marking at line 287. Because the recipient is Borsh-encoded and covered by the MPC signature, no relayer can substitute a different recipient. Every retry reverts identically, the Wormhole confirmation is never published, and the NEAR-side lock is never released, permanently freezing the user's funds.

## Finding Description
In `finTransfer` (`OmniBridge.sol` lines 283–322):

1. Line 287 sets `completedTransfers[payload.destinationNonce] = true`.
2. Lines 311–313 verify the MPC signature over the Borsh-encoded payload, which includes the recipient address at line 298.
3. Lines 317–322 attempt ETH delivery: `(bool success, ) = payload.recipient.call{value: payload.amount}("")`. On failure, `revert FailedToSendEther()` rolls back the entire transaction, including the nonce marking.

Because the nonce is never durably consumed and the recipient is immutably fixed in the MPC-signed payload, every subsequent call with the same payload reverts at the same point. `finTransferExtension` (`OmniBridgeWormhole.sol` lines 96–116) is only reached after the ETH delivery succeeds; if delivery always reverts, no Wormhole VAA is ever published to NEAR, so the NEAR-side lock is never released. There is no admin override, no pull-payment fallback, and no on-chain mechanism to signal failure back to NEAR or redirect the funds.

## Impact Explanation
Permanent freezing of bridged native ETH. A user who bridges native tokens from NEAR and specifies a contract address that cannot receive ETH (e.g., a Gnosis Safe, a DAO treasury, a custom contract wallet without `receive()`) as the EVM recipient will have their NEAR-side funds permanently locked. This matches the allowed critical impact: permanent freezing of bridged funds across NEAR and EVM.

## Likelihood Explanation
Moderate. Smart contract wallets, multisigs, and protocol treasury contracts are widely used as bridge recipients. Many such contracts do not implement `receive()` by default. The trigger requires only a standard user action — initiating a NEAR-to-EVM native token bridge transfer with a contract address as recipient — and no privileged access or attacker cooperation is needed. The condition is self-inflicted but not a user mistake in the traditional sense: the protocol provides no pre-transfer validation that the EVM recipient can accept ETH, and provides no recovery path once the condition is triggered.

## Recommendation
Replace the hard revert on failed ETH delivery with a pull-payment pattern. Mark the nonce as consumed and store the undeliverable amount in a mapping keyed by `destinationNonce` or `recipient`, then allow the recipient or a designated claimer to withdraw later. This prevents permanent fund loss while still consuming the nonce and allowing `finTransferExtension` to emit the Wormhole confirmation.

```solidity
struct PendingEth { address recipient; uint128 amount; }
mapping(uint64 => PendingEth) public pendingEthDeliveries;

// In finTransfer, replace the revert:
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) {
    pendingEthDeliveries[payload.destinationNonce] = PendingEth(payload.recipient, payload.amount);
}
// Continue to finTransferExtension so the Wormhole confirmation is always emitted.
```

A separate `claimPendingEth(uint64 destinationNonce)` function would allow the intended recipient to pull their ETH.

## Proof of Concept
1. User on NEAR initiates a native ETH bridge transfer specifying a Gnosis Safe (or any contract without `receive()`) as the EVM `recipient`.
2. NEAR MPC signs the `TransferMessagePayload` with `tokenAddress = address(0)`, `recipient = <contract without receive>`, and a unique `destinationNonce`.
3. Relayer calls `finTransfer` on EVM, attaching `payload.amount` ETH as `msg.value`.
4. `completedTransfers[nonce] = true` is set at line 287; signature is verified successfully at line 311.
5. `.call{value: payload.amount}("")` to the recipient fails (no `receive()` function).
6. `revert FailedToSendEther()` rolls back the entire transaction, including the nonce marking.
7. Relayer retries — same result every time; recipient is fixed in the signed payload.
8. `finTransferExtension` (Wormhole confirmation) is never reached; NEAR never receives proof of finalization.
9. User's NEAR-side funds remain permanently locked with no recovery path in the EVM contract.

A minimal Foundry test can demonstrate this: deploy a contract with no `receive()`, call `finTransfer` with a valid MPC-signed payload targeting it, and assert the transaction reverts with `FailedToSendEther` on every attempt while `completedTransfers[nonce]` remains `false`.