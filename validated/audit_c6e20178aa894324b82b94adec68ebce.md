Audit Report

## Title
ERC1155 `finTransfer` Permanently Freezes Bridged Tokens When Recipient Contract Lacks `IERC1155Receiver` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
`OmniBridge.finTransfer` delivers ERC1155 tokens via `IERC1155.safeTransferFrom`, which mandates that contract recipients implement `onERC1155Received`. If `payload.recipient` is a contract without this interface, every finalization attempt reverts. Because the recipient is cryptographically bound in the MPC-signed payload and no cancel or refund path exists, the ERC1155 tokens locked on the source chain by `initTransfer1155` are permanently frozen.

## Finding Description
In `finTransfer`, the nonce is marked consumed at line 287 before the transfer, but because the entire transaction reverts when `safeTransferFrom` fails, the nonce is never durably set — meaning the call can be retried indefinitely, yet will always revert with the same fixed recipient:

```solidity
// OmniBridge.sol L323-330
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

There is no `try/catch` around this call and no pre-flight `supportsInterface` check. The recipient address is Borsh-encoded and ECDSA-signed by the MPC at line 298 (`Borsh.encodeAddress(payload.recipient)`), making it immutable without a new MPC signature. On the source side, `initTransfer1155` irrevocably transfers custody to the bridge at lines 458–464 via `IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), ...)`. No `cancel`, `rescue`, `refund`, or `withdraw` function exists anywhere in `OmniBridge.sol`.

## Impact Explanation
This constitutes **permanent freezing of bridged funds**, matching the critical impact scope. The source-chain ERC1155 tokens are locked in the bridge with zero recovery path: every `finTransfer` attempt reverts, the MPC-signed payload cannot be altered to redirect to a different recipient, and no admin escape hatch exists in the contract (the UUPS upgradeability requires a separate governance action and is not a built-in recovery mechanism).

## Likelihood Explanation
Any unprivileged token holder can trigger this by calling `initTransfer1155` with a contract recipient that lacks `IERC1155Receiver`. Contract recipients are routine in bridge usage: Gnosis Safe multisigs, DAO treasuries, protocol vaults, and smart-contract wallets. No attacker cooperation is required — a user innocently bridging to their own multisig is sufficient. The condition is repeatable across any ERC1155 token registered in `multiTokens`.

## Recommendation
Wrap the `safeTransferFrom` in a `try/catch` and, on failure, credit the tokens to a per-recipient claimable escrow mapping that the recipient can pull later. Alternatively, perform a pre-flight `IERC165(payload.recipient).supportsInterface(type(IERC1155Receiver).interfaceId)` check and fall back to an escrow if it returns `false`. A third option is to use a non-safe low-level transfer if the underlying ERC1155 exposes one, accepting that the recipient must be aware of incoming tokens.

## Proof of Concept
1. User holds ERC1155 `(tokenAddress, tokenId=1)` on the source EVM chain.
2. User calls `initTransfer1155(tokenAddress, 1, 100, 0, 0, "gnosis-safe.near", "")` where the destination EVM recipient is a Gnosis Safe without `onERC1155Received`. 100 units are now held by the source-chain `OmniBridge`.
3. NEAR MPC signs a `TransferMessagePayload` with `recipient = GnosisSafeAddress`.
4. Relayer calls `finTransfer(sig, payload)` on the destination chain.
5. Execution reaches line 324: `IERC1155(multiToken.tokenAddress).safeTransferFrom(address(this), GnosisSafeAddress, 1, 100, "")`.
6. The ERC1155 contract calls `GnosisSafeAddress.onERC1155Received(...)` — reverts because the function does not exist.
7. The entire transaction reverts; `completedTransfers[nonce]` remains `false`.
8. All subsequent relay attempts revert identically. No alternative recipient can be substituted (payload is MPC-signed). No refund path exists.
9. The 100 ERC1155 tokens are permanently locked in the source-chain `OmniBridge`.

A local Foundry test can reproduce this by deploying a mock ERC1155, a mock recipient contract without `IERC1155Receiver`, pre-funding the destination bridge, and asserting that `finTransfer` always reverts while the source bridge balance never decreases.