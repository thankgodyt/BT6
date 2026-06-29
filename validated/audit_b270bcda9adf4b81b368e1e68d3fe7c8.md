Audit Report

## Title
Reentrancy via Malicious ERC1155 `safeTransferFrom` Corrupts `currentOriginNonce`, Enabling Unauthorized Minting on NEAR — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`initTransfer1155` increments `currentOriginNonce` at the top of the function but then re-reads the storage variable after an external call to a user-supplied `tokenAddress`. A malicious ERC1155 contract can reenter `initTransfer1155` during its `safeTransferFrom` implementation, causing the outer call to emit `InitTransfer` with the nonce written by the inner call. Two `InitTransfer` events are emitted with the same nonce while no tokens are locked, and the NEAR side mints tokens against the first submitted proof with zero EVM collateral.

## Finding Description

In `initTransfer1155` (lines 448–490 of `OmniBridge.sol`):

- **Line 448**: `currentOriginNonce += 1` increments the nonce to N+1 but does not capture it into a local variable.
- **Lines 458–464**: `IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "")` makes an external call to a fully attacker-controlled contract. No token allowlist exists for `initTransfer1155`.
- **Lines 471, 483**: `currentOriginNonce` is read from storage again — after the external call — for both `initTransferExtension` and the `InitTransfer` event.

A malicious token's `safeTransferFrom` can call back into `initTransfer1155` directly (it does not need to go through `onERC1155Received`). The `onERC1155Received` guard at lines 522–535 only blocks unsolicited direct ERC1155 sends to the bridge; it is not invoked by a malicious `safeTransferFrom` that skips the callback entirely.

Reentrancy trace (nonce starts at N):

| Step | Actor | `currentOriginNonce` | Event emitted |
|------|-------|----------------------|---------------|
| Outer call enters | Bridge | N+1 | — |
| `safeTransferFrom` called | Malicious token reenters | — | — |
| Inner call enters | Bridge | N+2 | — |
| Inner `safeTransferFrom` returns | Malicious token | N+2 | — |
| Inner call exits | Bridge | N+2 | `InitTransfer(nonce=N+2)` |
| Outer call resumes, reads storage | Bridge | N+2 | `InitTransfer(nonce=N+2)` ← duplicate |

Nonce N+1 is never emitted. Nonce N+2 is emitted twice. No tokens are locked in either call because the malicious token never updates balances.

No `nonReentrant` modifier exists anywhere in the EVM source tree (grep confirmed zero matches for `nonReentrant` and `ReentrancyGuard`).

This directly violates two documented invariants in `evm/CLAUDE.md` (lines 32–36):
- **"No replay attacks"**: "A nonce must never be reusable" — nonce N+2 is emitted in two events.
- **"Event–transfer atomicity"**: "`InitTransfer` must only be emitted in a code path where tokens have already been burned/locked" — both events are emitted with zero tokens locked.

The same structural flaw exists in `initTransfer` (lines 381, 418, 430) for ERC777-compatible ERC20 tokens, where `currentOriginNonce` is also read from storage after `safeTransferFrom`.

## Impact Explanation

The NEAR side treats any emitted `InitTransfer` event as proof that tokens are held on EVM (per `evm/CLAUDE.md` line 36). A relayer submits a proof of the inner `InitTransfer(nonce=N+2)` to NEAR. NEAR's `fin_transfer_callback` processes it and mints or unlocks tokens for `attacker.near`. The second proof (outer event, same nonce N+2) is rejected as a replay. The attacker receives bridged tokens on NEAR with zero EVM collateral locked.

This is **unauthorized minting of bridged tokens** — direct theft of protocol funds — matching the Critical allowed impact: *"unauthorized minting… of bridged funds across NEAR [or] EVM."*

## Likelihood Explanation

Any unprivileged user can call `initTransfer1155` with an arbitrary `tokenAddress`. There is no allowlist, no role requirement, and no registration step for ERC1155 tokens. Deploying a malicious ERC1155 contract requires no special permissions. The ERC1155 `safeTransferFrom` callback path is guaranteed by the standard and is not optional. The attack requires one transaction and one malicious contract deployment, and is repeatable indefinitely until the bridge is paused.

## Recommendation

1. **Capture the nonce into a local variable immediately after increment** and use only that local variable for all subsequent reads:

```solidity
uint64 nonce = ++currentOriginNonce;
// ... external call ...
initTransferExtension(msg.sender, deterministicToken, nonce, ...);
emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, nonce, ...);
```

Apply the identical fix to `initTransfer` (lines 381, 418, 430).

2. **Add `ReentrancyGuardUpgradeable`** from OpenZeppelin and apply `nonReentrant` to `initTransfer`, `initTransfer1155`, and `finTransfer` as defense-in-depth.

## Proof of Concept

**Malicious ERC1155 contract:**
```solidity
contract MaliciousERC1155 {
    OmniBridge bridge;
    bool reentered;

    function safeTransferFrom(
        address, address, uint256 id, uint256 amount, bytes memory
    ) external {
        if (!reentered) {
            reentered = true;
            // Reenter with zero msg.value — will revert on nativeFee math unless fee=0
            bridge.initTransfer1155(address(this), id, amount, 0, 0, "attacker.near", "");
        }
        // Return without transferring any tokens or calling onERC1155Received
    }
}
```

**Attack sequence:**
1. Deploy `MaliciousERC1155` pointing to `OmniBridge`.
2. Call `bridge.initTransfer1155(malicious, tokenId, amount, 0, 0, "attacker.near", "")` with sufficient `msg.value`.
3. Bridge increments `currentOriginNonce` to N+1, calls `malicious.safeTransferFrom(...)`.
4. Malicious token reenters: bridge increments nonce to N+2, inner `InitTransfer(nonce=N+2)` emitted, no tokens transferred.
5. Outer call resumes: reads `currentOriginNonce = N+2`, emits second `InitTransfer(nonce=N+2)`, no tokens transferred.
6. Relayer submits proof of inner `InitTransfer(nonce=N+2)` to NEAR.
7. NEAR mints tokens to `attacker.near` — zero EVM collateral locked.

**Verification test plan:** Write a Foundry test deploying `MaliciousERC1155` and `OmniBridge`, call `initTransfer1155`, and assert that two `InitTransfer` events with identical nonces are emitted and that the bridge's token balance remains zero.