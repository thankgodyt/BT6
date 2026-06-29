Audit Report

## Title
`HyperliquedBridgeToken` 3-arg `mint` permanently mis-delivers bridged funds to `_systemAddress` when `finTransfer` carries a non-empty `message` — (`File: evm/src/omni-bridge/contracts/HlBridgeToken.sol`)

## Summary

`HyperliquedBridgeToken` overrides the 3-arg `mint(address, uint256, bytes)` to call `_mint(account, value)` followed immediately by `_update(account, _systemAddress, value)`, netting `account` zero tokens and crediting `_systemAddress` with the full amount. `OmniBridge.finTransfer` dispatches to this 3-arg override whenever `payload.message.length != 0`. Any user who includes a non-empty `msg` when initiating a cross-chain transfer from NEAR to HyperEVM will have their entire bridged amount permanently deposited to `_systemAddress` instead of to themselves.

## Finding Description

**Root cause — 3-arg `mint` re-routes all tokens away from `account`:**

`HlBridgeToken.sol` lines 76–83:
```solidity
function mint(
    address account,
    uint256 value,
    bytes memory
) external override onlyOwner {
    _mint(account, value);
    _update(account, _systemAddress, value);   // net: account = 0, _systemAddress = value
}
```
The `_update(account, _systemAddress, value)` call is an internal ERC-20 transfer that moves the freshly minted tokens from `account` to `_systemAddress`. The test suite explicitly confirms this outcome (`HlBridgeToken.ts` L75–79): after calling the 3-arg mint, `balanceOf(user1) == 0` and `balanceOf(SYSTEM_ADDRESS) == 1000`.

**Dispatch path — `finTransfer` selects the 3-arg override on any non-empty message:**

`OmniBridge.sol` lines 337–349:
```solidity
} else if (isBridgeToken[payload.tokenAddress]) {
    if (payload.message.length == 0) {
        IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount);
    } else {
        IBridgeToken(payload.tokenAddress).mint(
            payload.recipient, payload.amount, payload.message
        );
    }
}
```
`HyperliquedBridgeToken` is registered via `addCustomToken` with `customMinter = address(0)`, so `isBridgeToken[tokenAddress] == true` and `customMinters[tokenAddress] == address(0)`. It falls squarely into this branch.

**Message population — user-supplied `msg` flows into `payload.message`:**

On the NEAR side (`near/omni-bridge/src/lib.rs` L487–500), `sign_transfer` builds `TransferMessagePayload.message` directly from the user-supplied `msg` field of `InitTransferMsg`. A non-empty user `msg` produces a non-empty `payload.message` on the EVM side, unconditionally triggering the 3-arg mint path.

**No existing guard prevents the mis-delivery.** The signature check in `finTransfer` only verifies MPC authenticity of the payload; it does not validate whether the 3-arg mint is appropriate for the registered token type. The `onlyOwner` modifier on `mint` is satisfied because `OmniBridge` is the token owner.

## Impact Explanation

Permanent, total loss of bridged funds — a concrete Critical impact under the allowed scope ("Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds"). The recipient receives 0 tokens. Tokens accumulate at `_systemAddress`. The only release mechanism, `coreReceiveWithData` with `ACTION_TRANSFER`, is gated to `msg.sender == _systemAddress` (`HlBridgeToken.sol` L114), a HyperCore system operation that no external user can invoke. There is no user-accessible recovery path.

## Likelihood Explanation

The `msg` field in `InitTransferMsg` is a standard, documented, user-facing parameter for cross-chain composability (e.g., DeFi calls on the destination chain). Any unprivileged user who sets a non-empty `msg` while targeting HyperEVM triggers the loss. No special privileges, front-running, or external compromise is required. The relayer finalizes the transfer exactly as MPC-signed; the bug fires deterministically on every such transfer.

## Recommendation

The 3-arg `mint` override must not re-route tokens away from `account` for the `finTransfer` (HyperEVM delivery) path. Two viable fixes:

1. **Remove the `_update` call from the `IBridgeToken`-conforming override** and introduce a separate, dedicated function (e.g., `mintForHyperCore`) called only by `coreReceiveWithData` internals:
```solidity
function mint(address account, uint256 value, bytes memory)
    external override onlyOwner {
    _mint(account, value);
    // No _update — HyperCore accounting is handled via coreReceiveWithData only.
}
```

2. **Alternatively**, if the 3-arg path must remain distinct, gate the `_update` re-route on a flag or separate entry point so that `finTransfer` never reaches it for HyperEVM-bound tokens.

## Proof of Concept

1. User calls `ft_transfer_call` on NEAR targeting HyperEVM with `msg = '{"InitTransfer":{"recipient":"hyp:0xUSER","fee":"0","native_token_fee":"0","msg":"some_dex_call"}}'`.
2. NEAR `sign_transfer` builds `TransferMessagePayload` with `message = b"some_dex_call"` (non-empty).
3. MPC signs; relayer calls `OmniBridge.finTransfer(sig, payload)` on HyperEVM.
4. `finTransfer`: `isBridgeToken[hlToken] == true`, `customMinters[hlToken] == address(0)`, `payload.message.length != 0` → calls `HyperliquedBridgeToken.mint(0xUSER, amount, b"some_dex_call")`.
5. Inside `mint`: `_mint(0xUSER, amount)` → `balanceOf(0xUSER) = amount`; then `_update(0xUSER, _systemAddress, amount)` → `balanceOf(0xUSER) = 0`, `balanceOf(_systemAddress) = amount`.
6. `0xUSER` receives 0 tokens. Funds are permanently stranded at `_systemAddress` with no user-accessible recovery path.

This is directly reproducible as a Hardhat integration test by extending the existing `HlBridgeToken.ts` suite: deploy `HyperliquedBridgeToken`, register it on `OmniBridge` via `addCustomToken(…, ZeroAddress, …)`, call `finTransfer` with a non-empty `message` field in the payload, and assert `balanceOf(recipient) == 0` and `balanceOf(SYSTEM_ADDRESS) == amount`.