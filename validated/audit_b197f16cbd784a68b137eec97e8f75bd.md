Audit Report

## Title
Permanent Freezing of Bridged ERC1155 Tokens via Non-Receiver Contract Recipient — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
In `finTransfer`, the ERC1155 branch unconditionally calls `IERC1155.safeTransferFrom` to the MPC-signed `payload.recipient`. If that recipient is a contract that does not implement `IERC1155Receiver`, the call reverts per the ERC-1155 standard. Because the `destinationNonce` assignment also reverts, the relayer can retry indefinitely — but the recipient is cryptographically committed in the MPC-signed payload, so every retry fails identically. The corresponding NEP-141 tokens are already burned on NEAR with no refund path, resulting in permanent loss of bridged funds.

## Finding Description
In `finTransfer`, the nonce is marked consumed at line 287 before any transfer occurs:

```solidity
completedTransfers[payload.destinationNonce] = true;
```

The ERC1155 delivery at lines 323–330 then calls:

```solidity
} else if (multiToken.tokenAddress != address(0)) {
    IERC1155(multiToken.tokenAddress).safeTransferFrom(
        address(this),
        payload.recipient,
        multiToken.tokenId,
        payload.amount,
        ""
    );
}
```

Per ERC-1155, `safeTransferFrom` invokes `onERC1155Received` on any contract recipient and reverts if the magic selector is not returned. When `payload.recipient` is a contract without `IERC1155Receiver`, the entire transaction reverts, rolling back the nonce assignment at line 287 as well. The relayer retries with the same MPC-signed payload — the same recipient — and the call reverts again, indefinitely. The NEAR-side burn that initiated the return leg is irreversible; there is no re-mint or refund mechanism on NEAR if EVM finalization permanently fails.

## Impact Explanation
This directly matches the allowed Critical impact: **permanent freezing of bridged funds**. The user's NEP-141 tokens are irreversibly burned on NEAR. The corresponding ERC1155 tokens remain locked inside the bridge contract on EVM. No admin rescue function exists in `OmniBridge.sol` to release locked ERC1155 tokens outside of `finTransfer`. Neither the user nor any relayer can alter the MPC-signed recipient; the transfer is permanently unfinalisable.

## Likelihood Explanation
Moderate. The affected class of recipients is large: multisig wallets not built on Safe, DAO treasuries, DeFi vaults, and any contract predating widespread ERC-1155 adoption. No special attacker capability is required. The trigger is the standard user-facing flow: `initTransfer1155` on EVM → NEAR mint → NEAR burn → `finTransfer` on EVM. A user who bridges ERC1155 tokens to a team treasury or protocol contract they control, without verifying `IERC1155Receiver` support, silently loses all funds.

## Recommendation
1. **Pre-flight ERC-165 check**: Before calling `safeTransferFrom`, check whether `payload.recipient` is a contract and, if so, query `IERC165(payload.recipient).supportsInterface(type(IERC1155Receiver).interfaceId)`. Revert with a descriptive error (e.g., `RecipientCannotReceiveERC1155`) so the failure is surfaced before NEAR-side funds are committed.
2. **Use non-safe `transferFrom`**: Replace `safeTransferFrom` with the non-safe `transferFrom` variant (where available on the underlying ERC-1155 implementation), bypassing the receiver callback. This removes the safety guarantee but eliminates the permanent-freeze vector.
3. **NEAR-side refund path**: Implement a timeout- or failure-proof-based mechanism on NEAR that allows re-minting burned NEP-141 tokens to the original sender if EVM finalization is proven to have permanently failed.

## Proof of Concept
1. Deploy an ERC1155 token; mint `tokenId=7`, amount=5 to `user`.
2. `user` calls `bridge.initTransfer1155(erc1155, 7, 5, 0, 0, "user.near", "")` — tokens locked in bridge.
3. NEAR bridge mints 5 NEP-141 units to `user.near`.
4. `user.near` initiates NEAR → EVM transfer specifying `recipient = 0xDAOContract` (a contract with no `onERC1155Received`).
5. NEP-141 tokens burned on NEAR; MPC signs payload committing `payload.recipient = 0xDAOContract`.
6. Relayer calls `bridge.finTransfer(sig, payload)`.
7. `IERC1155.safeTransferFrom(bridge, 0xDAOContract, 7, 5, "")` reverts — `0xDAOContract` returns no magic value.
8. Entire transaction reverts; `completedTransfers[nonce]` is not set.
9. Relayer retries — always reverts; signed recipient cannot be changed.
10. **Result**: 5 NEP-141 tokens permanently burned on NEAR; 5 ERC1155 tokens permanently locked in the EVM bridge.

A local Hardhat/Foundry test can reproduce this by deploying a minimal contract without `IERC1155Receiver`, constructing a valid MPC-signed payload targeting it, and asserting that `finTransfer` reverts on every call while the bridge's ERC1155 balance remains non-zero.