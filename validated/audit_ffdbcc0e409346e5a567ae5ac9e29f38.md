Audit Report

## Title
ERC721 Token Deposited via ERC20 `initTransfer` Path Causes Permanent Fund Lock - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary
`OmniBridge.initTransfer` performs no token-type validation before calling `SafeERC20.safeTransferFrom`. Because ERC721's `transferFrom(address,address,uint256)` shares the identical 4-byte ABI selector with ERC20's `transferFrom`, and `SafeERC20` accepts a no-return-data success, an ERC721 NFT can be silently deposited into the bridge. `finTransfer` then falls through to `IERC20.safeTransfer`, which reverts unconditionally on ERC721 (no `transfer(address,uint256)` exists), permanently locking the NFT while NEAR has already minted unbacked fungible tokens to the attacker.

## Finding Description
**Step 1 — Metadata registration (permissionless).**
`logMetadata` at L224–232 calls `IERC20Metadata(tokenAddress).name/symbol/decimals` with no interface check. Many ERC721 contracts (e.g., OpenZeppelin `ERC721URIStorage`) expose these functions. Calling `logMetadata(erc721Address)` succeeds and causes NEAR to deploy a fungible token keyed to the ERC721 address. This is explicitly documented as intentional in `evm/SECURITY.md` ("logMetadata and deployToken are permissionless: Anyone can call logMetadata for any ERC20 … by design"), but the design note does not account for ERC721 confusion.

**Step 2 — Deposit via `initTransfer` (L406–412).**
When `tokenAddress` is not in `customMinters` and not in `isBridgeToken`, the else-branch executes:
```solidity
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
```
`SafeERC20.safeTransferFrom` issues a low-level call to `token.transferFrom(from, to, value)`. ERC721's `transferFrom(address,address,uint256)` has the **identical selector** and does not return a bool; `SafeERC20` treats the no-return-data success as valid and does not revert. The NFT (tokenId passed as `amount`) is transferred into the bridge. The `InitTransfer` event is emitted; NEAR mints `tokenId` units of the fungible token to the attacker's NEAR account.

**Step 3 — Withdrawal permanently fails (`finTransfer` L315–355).**
For a raw ERC721 address:
- `multiTokens[payload.tokenAddress].tokenAddress == address(0)` → ERC1155 branch skipped.
- `customMinters[payload.tokenAddress] == address(0)` → custom minter branch skipped.
- `isBridgeToken[payload.tokenAddress] == false` → bridge token branch skipped.
- Falls to: `IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount)`.

ERC721 has no `transfer(address,uint256)` function. The low-level call hits an unmatched selector on a contract with code, causing an unconditional revert. Every `finTransfer` attempt reverts (the entire transaction reverts, including the nonce mark at L287, so the nonce is not consumed — but the NFT remains locked because the revert condition is structural and permanent). There is no admin rescue path or alternative withdrawal function.

## Impact Explanation
This concretely matches two allowed Critical impacts:
1. **Permanent freezing of bridged funds**: The ERC721 NFT is irrecoverably locked inside the bridge contract with no withdrawal path.
2. **Unauthorized minting / escrow mis-accounting**: NEAR mints `tokenId` units of a fungible token that are unbacked by any redeemable EVM-side asset. An attacker who sells those NEAR tokens extracts real value while the NFT remains frozen — a direct theft/escrow mis-accounting impact.

## Likelihood Explanation
The attack is fully permissionless and requires no privileged access, oracle manipulation, or front-running. Prerequisites are: (1) an ERC721 that exposes `name()`, `symbol()`, `decimals()` — common in OpenZeppelin-based ERC721 with metadata; (2) ownership of at least one token ID > 0 (tokenId = 0 would fail the `fee >= amount` check at L382 with `fee=0`); (3) approval granted to the bridge. The attack is repeatable for any qualifying ERC721 and any token ID.

## Recommendation
Add an ERC165 interface check at the top of `initTransfer` (and `logMetadata`) to reject tokens advertising ERC721 (`0x80ac58cd`) or ERC1155 (`0xd9b67a26`) support:

```solidity
if (IERC165(tokenAddress).supportsInterface(0x80ac58cd) ||
    IERC165(tokenAddress).supportsInterface(0xd9b67a26)) {
    revert UnsupportedTokenType();
}
```

Note: ERC165 `supportsInterface` is not universally implemented, so this should be combined with a try/catch and a token allowlist/denylist for defense in depth. Alternatively, enforce an explicit ERC20 whitelist at the `initTransfer` entry point, analogous to how `multiTokens` already separates ERC1155 handling.

## Proof of Concept
1. Deploy an ERC721 contract that also implements `name()`, `symbol()`, `decimals()` (e.g., extend OpenZeppelin `ERC721URIStorage` and add a `decimals()` returning 0).
2. Call `bridge.logMetadata(erc721Address)` — succeeds; NEAR deploys a fungible token for the ERC721 address.
3. Mint tokenId `N` (N > 0) to the attacker address; call `erc721.approve(bridgeAddress, N)`.
4. Call `bridge.initTransfer(erc721Address, N, 0, 0, "attacker.near", "")`:
   - `fee=0 < amount=N` → passes L382 check.
   - Falls to else-branch at L406; `SafeERC20.safeTransferFrom` resolves to ERC721's `transferFrom(attacker, bridge, N)` — succeeds (no bool returned, SafeERC20 accepts).
   - `InitTransfer` event emitted; NEAR mints N fungible tokens to `attacker.near`.
5. Attacker transfers/sells the NEAR fungible tokens.
6. Call `bridge.finTransfer(sig, {tokenAddress: erc721Address, amount: N, recipient: X, ...})`:
   - All three special-case branches skipped (no multiToken, no customMinter, not isBridgeToken).
   - `IERC20(erc721Address).safeTransfer(X, N)` → reverts (no `transfer` selector on ERC721).
   - Transaction reverts entirely; NFT remains in bridge with no recovery path.
7. Assert: `erc721.ownerOf(N) == bridgeAddress` (NFT locked), NEAR-side tokens exist and are unbacked.