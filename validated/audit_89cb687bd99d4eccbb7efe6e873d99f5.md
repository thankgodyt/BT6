Looking at the actual code in `OmniBridge.sol` to verify each claim in the report.

Audit Report

## Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 Token Enables Unauthorized Minting on NEAR — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`initTransfer1155` increments `currentOriginNonce` before the external `IERC1155.safeTransferFrom` call but reads the storage variable again after it to populate `initTransferExtension` and the emitted `InitTransfer` event. A malicious ERC1155 token can reenter `initTransfer1155` during `safeTransferFrom`, causing the outer call to emit a duplicate `InitTransfer` event with the same nonce as the inner call. Neither call locks any tokens on EVM, but NEAR processes the first event and mints bridged tokens to the attacker.

## Finding Description

The execution sequence in `initTransfer1155` (lines 447–489) is:

```
currentOriginNonce += 1;                              // L448 — nonce becomes N
IERC1155(tokenAddress).safeTransferFrom(...);         // L458 — external call to untrusted token
initTransferExtension(..., currentOriginNonce, ...);  // L471 — reads storage AFTER external call
emit BridgeTypes.InitTransfer(..., currentOriginNonce, ...); // L483 — reads storage AFTER external call
```

Because `currentOriginNonce` is a storage variable read at steps 3 and 4 after the external call at step 2, any reentrant modification during step 2 is reflected in the event emitted by the outer call.

**Attack path:**

1. Attacker deploys `MaliciousERC1155` whose `safeTransferFrom` reenters `initTransfer1155` once (using a `reentered` flag to prevent infinite recursion) and then returns without transferring tokens or calling `onERC1155Received`.
2. Attacker calls the permissionless `logMetadata1155(MaliciousERC1155, tokenId)` to register the token on NEAR.
3. NEAR processes the `LogMetadata` event and registers the token.
4. Attacker calls `initTransfer1155(MaliciousERC1155, tokenId, amount, ...)`:
   - `currentOriginNonce` becomes **N**.
   - `MaliciousERC1155.safeTransferFrom` is called. The malicious token reenters `initTransfer1155`:
     - **Inner call**: `currentOriginNonce` becomes **N+1**. Inner `safeTransferFrom` (with `reentered = true`) returns without transferring tokens. Inner call emits `InitTransfer(nonce=N+1)` — no tokens locked.
   - Outer `safeTransferFrom` returns without transferring tokens.
   - Outer call reads `currentOriginNonce` = **N+1** (overwritten by inner call).
   - Outer call emits `InitTransfer(nonce=N+1)` — duplicate.
5. NEAR sees two `InitTransfer` events with nonce N+1. It processes the first and mints tokens to the attacker. It rejects the second as a replay.
6. Nonce N is never emitted. No tokens were locked on EVM for either event.

**Why `onERC1155Received` does not mitigate this:** The bridge calls `IERC1155(tokenAddress).safeTransferFrom(...)` on the untrusted token contract. A malicious token's `safeTransferFrom` implementation can skip calling `onERC1155Received` on the bridge entirely and still return normally. The bridge has no mechanism to enforce that `onERC1155Received` is invoked. The guard at lines 529–531 only fires if the token chooses to call it.

The same root cause exists in `initTransfer` for ERC20 tokens: `currentOriginNonce` is also read after the external `safeTransferFrom` call (lines 418 and 430), though ERC20 tokens do not have a receiver callback, making reentrancy there harder to trigger in practice.

No `ReentrancyGuardUpgradeable` is imported and no `nonReentrant` modifier is applied to any transfer-initiating function. The security invariant in `evm/CLAUDE.md` line 34 — *"Always mutate state before any external call"* — is violated: the nonce is incremented before the external call but read after it. The event–transfer atomicity invariant (line 36) — *"InitTransfer must only be emitted in a code path where tokens have already been burned/locked"* — is also violated.

## Impact Explanation

An unprivileged attacker can mint an arbitrary quantity of bridged tokens on NEAR without locking any corresponding tokens on the EVM side. This directly breaks the lock/mint invariant of the bridge, constitutes unauthorized minting, and inflates the NEAR-side token supply while the EVM-side escrow holds nothing. This matches the allowed critical impact: **unauthorized minting of bridged funds** and **escrow mis-accounting / balance manipulation**.

## Likelihood Explanation

The attack requires only: deploying a malicious ERC1155 contract (no special permissions), calling the permissionless `logMetadata1155` to register it, and calling `initTransfer1155` with the malicious token. No admin compromise, no MPC collusion, no front-running, and no victim interaction is required. Any unprivileged bridge user can execute this attack repeatably.

## Recommendation

1. **Capture the nonce in a local variable before any external call** and use that local variable in `initTransferExtension` and `emit`:

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    uint64 nonce = currentOriginNonce; // capture before external call
    ...
    IERC1155(tokenAddress).safeTransferFrom(...);
    ...
    initTransferExtension(..., nonce, ...);
    emit BridgeTypes.InitTransfer(..., nonce, ...);
}
```

Apply the same fix to `initTransfer` (lines 418 and 430).

2. **Add `ReentrancyGuardUpgradeable` and the `nonReentrant` modifier** to `initTransfer`, `initTransfer1155`, and `finTransfer` as defense-in-depth, consistent with the documented security invariant.

## Proof of Concept

```solidity
contract MaliciousERC1155 is ERC1155 {
    OmniBridge bridge;
    bool reentered;

    constructor(address _bridge) ERC1155("") { bridge = OmniBridge(_bridge); }

    function safeTransferFrom(
        address from, address to, uint256 id, uint256 amount, bytes memory
    ) public override {
        if (!reentered) {
            reentered = true;
            // Inner call: increments nonce to N+1, emits InitTransfer(N+1), no tokens locked
            bridge.initTransfer1155(address(this), id, amount, 0, 0, "attacker.near", "");
            reentered = false;
        }
        // Return without transferring tokens and without calling onERC1155Received
    }
}

// Test sequence:
// 1. Deploy MaliciousERC1155(bridge)
// 2. bridge.logMetadata1155(malicious, tokenId)  // permissionless
// 3. bridge.initTransfer1155(malicious, tokenId, amount, 0, 0, "attacker.near", "")
//    → emits InitTransfer(nonce=N+1) twice, no tokens locked
// 4. NEAR mints tokens for the first InitTransfer(N+1) event
```

A Foundry invariant test asserting `bridge.currentOriginNonce() == tokensLockedInBridge` would catch this: after the attack, the nonce is N+1 but zero tokens are held in escrow.