Audit Report

## Title
Re-entrancy in `initTransfer1155` via Malicious ERC1155 Allows Unauthorized Token Minting on NEAR — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
`initTransfer1155` increments `currentOriginNonce` in storage at line 448, then makes an external call to `IERC1155.safeTransferFrom` at line 458, and finally emits `InitTransfer` reading `currentOriginNonce` from storage again at line 483. A malicious ERC1155 contract can re-enter `initTransfer1155` during the `safeTransferFrom` callback, causing both the inner and outer calls to emit `InitTransfer` events carrying the same nonce (N+2), while nonce N+1 is never emitted. The NEAR side finalizes one event and mints bridged tokens to the attacker, while the bridge holds zero locked EVM-side collateral.

## Finding Description
`currentOriginNonce` is a plain storage variable (line 45). `initTransfer1155` follows this sequence:

```
L448: currentOriginNonce += 1;          // storage write → N+1
L458: IERC1155(tokenAddress)
          .safeTransferFrom(...);        // external call — re-entry point
L483: emit BridgeTypes.InitTransfer(
          ..., currentOriginNonce, ...); // reads storage again
```

Because the emit reads from storage rather than a local variable captured before the external call, any mutation of `currentOriginNonce` during the external call is reflected in the outer call's event.

The only guard against unsolicited ERC1155 callbacks is `onERC1155Received` (lines 522–535):

```solidity
if (operator != address(this)) revert ERC1155DirectSendNotAllowed();
```

`operator` is the address that called `safeTransferFrom` on the ERC1155 contract. Because `initTransfer1155` is the caller, `operator == address(this)` is always true. A malicious ERC1155 can call `onERC1155Received(msg.sender, ...)` — where `msg.sender` is the bridge — and the guard passes unconditionally. The malicious token can then re-enter `initTransfer1155` without ever transferring any tokens.

`logMetadata1155` (lines 234–270) has no access-control modifier, so any attacker can register a malicious token address with the bridge before the attack.

There is no `ReentrancyGuard` or `nonReentrant` modifier anywhere in `OmniBridge`.

Re-entry execution trace (nonce starts at N):

| Step | Effect |
|---|---|
| Outer `initTransfer1155` called | `currentOriginNonce` → N+1 |
| Bridge calls `safeTransferFrom` on malicious token | Malicious token calls `onERC1155Received(bridge, ...)` → guard passes; re-enters `initTransfer1155` |
| Inner `initTransfer1155` executes | `currentOriginNonce` → N+2; inner `safeTransferFrom` called; no tokens transferred; inner emits `InitTransfer(nonce=N+2)` |
| Outer `safeTransferFrom` returns | Outer emits `InitTransfer(nonce=N+2)` — reads storage, which is now N+2 |

Result: two `InitTransfer` events share nonce N+2; nonce N+1 is never emitted; bridge holds zero locked tokens.

## Impact Explanation
This is a **Critical** unauthorized minting and escrow mis-accounting impact. NEAR observes a valid-looking `InitTransfer` event and mints bridged tokens to the attacker. The bridge holds zero EVM-side collateral for either transfer. This directly matches the allowed impact class: "unauthorized minting" and "escrow mis-accounting that changes user or protocol balances."

## Likelihood Explanation
The attacker requires no privileged role. The three required steps — deploy a malicious ERC1155, call the permissionless `logMetadata1155`, and call `initTransfer1155` — are all available to any unprivileged external user. The `onERC1155Received` guard is structurally bypassed by design whenever the bridge is the `safeTransferFrom` caller. The attack is repeatable with no front-running dependency or external oracle. Likelihood is **high**.

## Recommendation
1. **Cache the nonce in a local variable** before any external call and use that local variable in the emit:
   ```solidity
   uint64 nonce = ++currentOriginNonce;
   // ... external calls ...
   emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, nonce, ...);
   ```
2. **Add `nonReentrant`** from OpenZeppelin's `ReentrancyGuardUpgradeable` to both `initTransfer` and `initTransfer1155`.
3. Apply the same local-variable fix to `initTransfer` (lines 381/430), which has an identical nonce-in-storage-emit pattern exploitable via ERC777 `tokensToSend` hooks.

## Proof of Concept
1. Deploy `MaliciousERC1155(bridge)` whose `safeTransferFrom` (a) calls `onERC1155Received(msg.sender, ...)` on the bridge to satisfy the guard, (b) re-enters `initTransfer1155` once, and (c) never transfers tokens.
2. Call `bridge.logMetadata1155(malicious, tokenId)` — succeeds with no access control.
3. Call `bridge.initTransfer1155(malicious, tokenId, amount, 0, 0, "near:attacker.near", "")`.
4. Observe two `InitTransfer` events both carrying nonce N+2 in the transaction logs; nonce N+1 is absent.
5. NEAR finalizes one event and mints tokens to the attacker; the bridge's ERC1155 balance for the malicious token remains zero.