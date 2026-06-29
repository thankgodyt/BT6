Audit Report

## Title
ERC1155 `safeTransferFrom` Mandatory Receiver Callback in `finTransfer` Permanently Freezes Bridged Funds When Recipient Contract Lacks `IERC1155Receiver` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
`finTransfer` in `OmniBridge.sol` delivers ERC1155 tokens via `IERC1155.safeTransferFrom`, which unconditionally invokes `onERC1155Received` on any contract recipient and reverts if the selector is not returned. Because the nonce write at line 287 is also reverted on failure, the relayer retries indefinitely with identical results. The NEAR side has already committed the lock or burn, so the ERC1155 tokens are permanently frozen: undeliverable on EVM, irrecoverable on NEAR, with no in-contract rescue path.

## Finding Description
In `finTransfer` (lines 279–355 of `OmniBridge.sol`), the nonce is marked used before the transfer:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287
```

Then, for ERC1155 tokens, delivery is attempted via:

```solidity
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this),
    payload.recipient,
    multiToken.tokenId,
    payload.amount,
    ""
);   // lines 324–330
```

EIP-1155 mandates that `safeTransferFrom` call `onERC1155Received` on any contract recipient and revert if the correct selector is not returned. If `payload.recipient` is a contract that does not implement `IERC1155Receiver` (e.g., a Gnosis Safe multisig, a DAO treasury, or a DeFi vault), the ERC1155 token contract reverts, which cascades to revert the entire `finTransfer` transaction — including the nonce write. The nonce is therefore never consumed, and the relayer can retry, but every retry fails identically because the recipient's code is immutable.

The contract itself is aware of the ERC1155 receiver requirement: `onERC1155Received` (lines 522–535) explicitly rejects any operator that is not `address(this)`, and `supportsInterface` (lines 510–520) deliberately omits `IERC1155Receiver` advertisement. Yet no equivalent guard is applied to `payload.recipient` before `safeTransferFrom` is called.

No rescue, redirect, or emergency-withdrawal function exists in the contract for stuck ERC1155 tokens. The full admin surface (lines 548–596) consists only of `pause`, `pauseAll`, `upgradeToken`, and `setNearBridgeDerivedAddress` — none of which can recover ERC1155 tokens held by the bridge for a failed delivery.

## Impact Explanation
**Critical — permanent freezing of bridged ERC1155 funds.** A user who bridges ERC1155 tokens from NEAR to an EVM contract address that does not implement `IERC1155Receiver` will have their tokens locked or burned on NEAR with no possibility of EVM-side delivery. The `finTransfer` call reverts on every relay attempt, the nonce is never consumed, and no in-contract mechanism exists to redirect or rescue the stuck transfer. The loss is total and irreversible within the current contract code. This matches the allowed critical impact class: permanent freezing of bridged funds across NEAR and EVM.

## Likelihood Explanation
**Medium.** The ERC1155 delivery path is activated for any token registered via `logMetadata1155`. A large class of common contract recipients — Gnosis Safe multisigs (pre-ERC1155 support), DAO treasuries, generic proxy contracts, and DeFi vaults — do not implement `IERC1155Receiver`. A user bridging ERC1155 tokens from NEAR to any such address will permanently lose their funds. The user has no on-chain mechanism to verify whether the target contract implements the required interface before committing the transfer on the NEAR side, and the bridge provides no warning or pre-flight check.

## Recommendation
1. **Pull-based delivery**: Replace `safeTransferFrom` with a claimable escrow pattern. Store the tokens in a `pendingClaims[recipient]` mapping and let the recipient pull them via a separate `claim()` function, eliminating the mandatory callback entirely.
2. **Use `transferFrom` instead of `safeTransferFrom`**: The non-safe variant does not invoke `onERC1155Received`, removing the revert risk at the cost of the safety check.
3. **Wrap in `try/catch`**: Surround the `safeTransferFrom` call in a Solidity `try/catch` block. On failure, store the amount in a claimable mapping rather than reverting the entire transaction, so the nonce is consumed and the relayer is not stuck in an infinite retry loop.

## Proof of Concept
1. An ERC1155 token is registered on the bridge via `logMetadata1155(tokenAddress, tokenId)`, creating a `multiTokens` entry for the deterministic address.
2. A user on EVM calls `initTransfer1155` to bridge ERC1155 tokens to NEAR; the bridge takes custody of the tokens. On NEAR, the user later initiates a return transfer specifying as recipient a deployed EVM contract (e.g., a Gnosis Safe or DeFi vault) that does not implement `IERC1155Receiver`. The NEAR contract locks or burns the tokens.
3. The relayer constructs a valid MPC-signed `TransferMessagePayload` and calls `finTransfer(signatureData, payload)` on `OmniBridge`.
4. Signature check passes (line 311). `completedTransfers[payload.destinationNonce]` is set to `true` (line 287). Execution reaches the ERC1155 branch (line 323) and calls `IERC1155(multiToken.tokenAddress).safeTransferFrom(address(this), payload.recipient, ...)`.
5. The ERC1155 token contract calls `onERC1155Received` on `payload.recipient`. The recipient has no such function; the call reverts.
6. The entire `finTransfer` transaction reverts. `completedTransfers[payload.destinationNonce]` is also reverted to `false`.
7. The relayer retries. Steps 4–6 repeat indefinitely.
8. The user's ERC1155 tokens are permanently frozen: locked in the bridge on EVM (undeliverable), burned/locked on NEAR (irrecoverable), with no admin rescue path available in the current contract.