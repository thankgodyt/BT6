Audit Report

## Title
ERC1155 `safeTransferFrom` in `finTransfer` Permanently Freezes Bridged Tokens When Recipient Is a Contract Without `onERC1155Received` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
In `finTransfer()`, ERC1155 token delivery uses `IERC1155.safeTransferFrom()`, which unconditionally reverts if the recipient contract does not implement `onERC1155Received()`. Because the recipient is cryptographically bound in the MPC-signed payload, no relayer can substitute an alternative address. The NEAR-side assets are already locked or burned, and the EVM-side ERC1155 tokens held by the bridge can never be delivered, resulting in permanent fund loss with no on-chain recovery path.

## Finding Description
In `finTransfer()`, after the nonce guard and signature verification, the ERC1155 delivery branch executes:

```solidity
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this),
    payload.recipient,
    multiToken.tokenId,
    payload.amount,
    ""
);
```

Per EIP-1155, `safeTransferFrom` MUST call `onERC1155Received()` on any contract recipient and MUST revert if the hook is absent or returns the wrong selector. The `completedTransfers[payload.destinationNonce] = true` write at line 287 occurs before this call; when `safeTransferFrom` reverts, the entire transaction reverts, including the nonce write. The nonce is therefore never durably consumed.

The `payload.recipient` is Borsh-encoded and covered by the MPC ECDSA signature (lines 289–313). No relayer can alter the recipient field without invalidating the signature. Every subsequent call to `finTransfer` with the original payload will revert at the same point. The contract contains no admin rescue function, no alternative delivery path, and no refund mechanism for stuck ERC1155 balances.

By contrast, the native ETH delivery path (lines 319–322) uses a low-level `.call{value: ...}("")` with a success check, gracefully handling contract recipients. The ERC1155 path has no equivalent fallback.

## Impact Explanation
This constitutes permanent freezing of bridged funds — an explicitly listed Critical impact. The user's ERC1155 tokens are locked or burned on NEAR via `initTransfer1155`, and the corresponding tokens held by the EVM bridge contract can never be delivered to the specified recipient. There is no on-chain recovery function. The loss is irreversible.

## Likelihood Explanation
Any user who specifies a smart contract as the EVM recipient — a Gnosis Safe, a DAO treasury, a DeFi vault, or any proxy contract — that does not implement `IERC1155Receiver` triggers this condition. This is a routine, legitimate use case. No malicious intent is required; an honest user bridging ERC1155 tokens to their multisig wallet is sufficient to trigger permanent fund loss.

## Recommendation
Replace `safeTransferFrom` with a low-level call that bypasses the receiver hook, or wrap the call in a `try/catch` with a fallback delivery mechanism (e.g., storing the tokens as claimable by the recipient). Additionally, add an admin-callable rescue function to recover stuck ERC1155 balances from the bridge contract. The ETH delivery path's pattern of checking success without reverting on failure is a useful model.

## Proof of Concept
1. User holds ERC1155 token (`tokenAddress = 0xAAA`, `tokenId = 1`) on NEAR and calls `initTransfer1155` specifying `recipient = 0xVault` (an EVM contract without `onERC1155Received`, e.g., a Gnosis Safe).
2. NEAR bridge locks/burns the tokens and emits a cross-chain event. MPC nodes sign a `TransferMessagePayload` with `recipient = 0xVault`.
3. Relayer calls `finTransfer(signature, payload)` on EVM `OmniBridge`.
4. `completedTransfers[nonce] = true` is written at line 287; `safeTransferFrom(bridge, 0xVault, tokenId, amount, "")` is called at line 324.
5. `0xVault` has no `onERC1155Received` → ERC1155 reverts → entire transaction reverts, including the nonce write.
6. Relayer retries; every attempt reverts identically. ERC1155 tokens remain in the bridge contract. NEAR-side assets are permanently gone. No admin function exists to recover them.

**Minimal test**: Deploy a mock ERC1155 token, register it in `multiTokens`, fund the bridge with tokens, then call `finTransfer` with a recipient that is a plain contract (no `onERC1155Received`). Assert the transaction reverts and `completedTransfers[nonce]` remains `false`. Confirm no recovery path exists.