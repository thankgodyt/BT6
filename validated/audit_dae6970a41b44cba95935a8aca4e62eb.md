Audit Report

## Title
Missing Self-Address Validation in `finTransfer` Allows Permanent Freezing of Bridged Tokens — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary
`OmniBridge.sol::finTransfer` dispatches tokens to `payload.recipient` across all four token-type branches without checking whether `payload.recipient == address(this)`. A NEAR user can specify the EVM OmniBridge contract address as the transfer recipient; the NEAR side only rejects NEAR-chain recipients, not the bridge contract address itself. When a relayer submits the MPC-signed payload, tokens are minted or transferred into the OmniBridge contract with no recovery path, permanently freezing them.

## Finding Description
`finTransfer` (lines 279–367 of `OmniBridge.sol`) verifies the MPC signature and then dispatches tokens through one of four branches, none of which guard against `payload.recipient == address(this)`:

- **ETH** (`tokenAddress == address(0)`): `payload.recipient.call{value: payload.amount}("")` succeeds because the contract has `receive() external payable {}` (line 574). ETH is stuck with no withdrawal function.
- **ERC1155**: `IERC1155.safeTransferFrom(address(this), address(this), ...)` triggers `onERC1155Received` on OmniBridge. The guard at line 530 checks `operator != address(this)` — but the operator is OmniBridge itself (the caller of `safeTransferFrom`), so the check passes and the transfer succeeds. Tokens are stuck.
- **Bridge tokens** (`isBridgeToken`): `IBridgeToken(payload.tokenAddress).mint(address(this), amount)` mints tokens into OmniBridge. OmniBridge is the token owner and can call `burn(account, value)`, but no internal function exists to burn tokens held by the contract itself. `initTransfer` only burns from `msg.sender` (line 405), not from the contract's own balance.
- **Native ERC20**: `IERC20(payload.tokenAddress).safeTransfer(address(this), amount)` transfers tokens into OmniBridge. There is no sweep or recovery function anywhere in the contract.

The root cause on the NEAR side is that `init_transfer` (lib.rs line 531–534) only rejects `ChainKind::Near` recipients; it does not prevent a user from supplying the EVM OmniBridge contract address as the EVM recipient. The NEAR MPC signs the payload containing that address without inspecting it, and a standard relayer submits it to `finTransfer`.

## Impact Explanation
This is a direct instance of **permanent freezing of bridged funds**, which is explicitly listed as a Critical allowed impact. For bridge tokens, the total supply is inflated (tokens are minted) but held irrecoverably by OmniBridge. For native ERC20 tokens, the locked collateral pool is inflated with no sweep mechanism. For ETH, native value is permanently locked. There is no admin rescue path: no sweep function, no emergency withdrawal, and no way for OmniBridge to call `initTransfer` on its own behalf to burn or re-bridge the stuck tokens.

## Likelihood Explanation
Any unprivileged NEAR user can trigger this by calling `ft_on_transfer` with `recipient = OmniAddress::Eth(<omni_bridge_address>)`. No special role, admin compromise, or MPC collusion is required. The NEAR bridge accepts any EVM address as recipient (only rejecting NEAR-chain recipients). A standard relayer then submits `finTransfer`. The attack can occur accidentally (user pastes the wrong address) or deliberately as a griefing/sabotage action against the bridge's token supply accounting.

## Recommendation
Add a self-address guard at the top of `finTransfer`, immediately after signature verification:

```solidity
if (payload.recipient == address(this)) {
    revert InvalidRecipient();
}
```

Symmetrically, on the NEAR side in `process_fin_transfer_to_near`, add a check that `recipient != env::current_account_id()` before calling `send_tokens`.

## Proof of Concept
1. On NEAR, call `ft_on_transfer` (or `init_transfer`) specifying `recipient = OmniAddress::Eth(<OmniBridge_contract_address>)` and any supported token with a non-zero amount.
2. The NEAR bridge accepts the transfer (only `ChainKind::Near` is rejected at line 531–534 of `lib.rs`).
3. The NEAR MPC signs the `TransferMessagePayload` containing `recipient = <OmniBridge_address>`.
4. A relayer (or the attacker) calls `OmniBridge.finTransfer(signatureData, payload)`.
5. Signature verification passes. The appropriate branch executes: for a bridge token, `IBridgeToken.mint(address(OmniBridge), amount)` is called; for a native ERC20, `safeTransfer(address(OmniBridge), amount)` is called.
6. Tokens are now held by OmniBridge with no function to recover them. The `completedTransfers[nonce]` flag is set, preventing replay, but the funds are permanently frozen.

A local integration test can demonstrate this by deploying OmniBridge and a BridgeToken, constructing a valid signed payload with `recipient = address(OmniBridge)`, calling `finTransfer`, and asserting that `BridgeToken.balanceOf(address(OmniBridge)) == amount` with no subsequent recovery possible.