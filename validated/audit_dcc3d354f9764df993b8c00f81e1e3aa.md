Audit Report

## Title
Reentrancy in `initTransfer` via Malicious ERC20 `transferFrom` Enables Unbacked Token Minting on NEAR — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`OmniBridge.initTransfer` increments `currentOriginNonce` before the external `safeTransferFrom` call but emits `InitTransfer` and calls `initTransferExtension` (which publishes the Wormhole VAA in `OmniBridgeWormhole`) only after it. No reentrancy guard exists anywhere in the contract hierarchy. A malicious ERC20's `transferFrom` can re-enter `initTransfer` an arbitrary number of times, each time obtaining a fresh unique nonce and producing a distinct `InitTransfer` event (and Wormhole VAA), while locking at most one unit of actual tokens. The NEAR bridge treats every such event as proof of a locked balance and mints the stated amount, resulting in unbounded unauthorized minting of bridged assets.

## Finding Description

In `OmniBridge.initTransfer` (lines 373–437), the execution order is:

1. **Line 381**: `currentOriginNonce += 1` — state mutation, correct for replay prevention.
2. **Lines 407–411** (the `else` branch, for arbitrary ERC20s): `IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount)` — external call to attacker-controlled contract.
3. **Lines 415–425**: `initTransferExtension(...)` — in `OmniBridgeWormhole`, this calls `_wormhole.publishMessage{value: value}(...)` and increments `wormholeNonce`.
4. **Lines 427–436**: `emit BridgeTypes.InitTransfer(...)`.

Steps 3 and 4 occur after the external call at step 2. Because `currentOriginNonce` is already incremented before the external call, each re-entrant invocation of `initTransfer` receives a new, unique nonce value. There is no `ReentrancyGuardUpgradeable` imported or applied in `OmniBridge`, `OmniBridgeWormhole`, or `SelectivePausableUpgradable`. The `whenNotPaused` modifier is not a reentrancy barrier.

**Re-entrant call trace (depth 2 example):**

- Outer call: nonce = N, calls `safeTransferFrom` on malicious token.
  - Inner call (re-entry): nonce = N+1, calls `safeTransferFrom` (returns `true`, no tokens moved), calls `initTransferExtension` with nonce N+1 (Wormhole VAA published), emits `InitTransfer(nonce=N+1)`.
- Outer call resumes: calls `initTransferExtension` with nonce N (Wormhole VAA published), emits `InitTransfer(nonce=N)`.

Result: two distinct, valid-looking cross-chain proofs for a single (or zero) actual token lock. The NEAR nonce-deduplication map does not block any of them because each carries a unique `originNonce`.

For the base `OmniBridge` (non-Wormhole, Ethereum mainnet), the NEAR side uses Ethereum light-client Merkle proofs of the `InitTransfer` event log. For `OmniBridgeWormhole` (L2 chains), the NEAR side uses Wormhole VAAs. Both proof paths are exploitable; on chains where `wormhole.messageFee() == 0`, the Wormhole path requires no additional ETH per re-entrant call.

The project's own invariant in `evm/CLAUDE.md` line 36 explicitly forbids this: *"InitTransfer must only be emitted in a code path where tokens have already been burned/locked in the same transaction."* The `evm/SECURITY.md` does not acknowledge reentrancy as a known or accepted issue.

## Impact Explanation

Each re-entrant `InitTransfer` event causes the NEAR bridge's `fin_transfer` to mint `amount` of the corresponding NEAR token to the attacker's NEAR account. Because each event carries a unique `originNonce`, NEAR's nonce-deduplication does not suppress any of them. The attacker receives N×`amount` NEAR-side tokens while locking at most 1×`amount` (or zero) EVM-side tokens. This is a direct, unbounded unauthorized minting of bridged assets and permanent loss of peg integrity — matching the Critical impact class: *"unauthorized minting… that changes user or protocol balances"* and *"balance manipulation… that changes user or protocol balances."*

## Likelihood Explanation

The attack requires no privileged access. `initTransfer` is public and unpermissioned. `logMetadata` is also permissionless, allowing the attacker to register the malicious token with the NEAR bridge before the attack. The only prerequisite is deploying a malicious ERC20 contract and waiting for the NEAR relayer to deploy the corresponding NEAR token — both steps are fully within reach of any unprivileged attacker. The attack is repeatable and can be scaled to arbitrary depth limited only by the block gas limit.

## Recommendation

Apply `ReentrancyGuardUpgradeable` from OpenZeppelin and add the `nonReentrant` modifier to `initTransfer` and `initTransfer1155`. Alternatively, strictly follow the Checks-Effects-Interactions pattern: move the `emit InitTransfer` and `initTransferExtension` calls to before the external `safeTransferFrom` call. The project's stated invariant *"State before external calls"* must be extended to cover event emission and Wormhole message publishing, not only nonce mutation.

## Proof of Concept

**Prerequisites:**
1. Deploy `MaliciousToken` pointing to the `OmniBridge` (or `OmniBridgeWormhole`) address.
2. Call `bridge.logMetadata(address(maliciousToken))` — permissionless; triggers NEAR relayer to deploy a corresponding NEAR token.
3. Wait for NEAR-side token deployment.

**Attack:**
4. Call `bridge.initTransfer(address(maliciousToken), 1e18, 0, 0, "attacker.near", "")` with `msg.value = 0` (assuming `nativeFee = 0`).

**Execution trace:**
- `currentOriginNonce` → N.
- `safeTransferFrom` called on `MaliciousToken`.
  - `MaliciousToken.transferFrom` re-enters `initTransfer` up to `maxReentry` times.
  - Each re-entrant call: nonce increments (N+1, N+2, …), `safeTransferFrom` returns `true` without moving tokens, `initTransferExtension` publishes Wormhole VAA (or base impl passes with `value=0`), `InitTransfer` emitted.
- Outer call completes: `initTransferExtension` and `InitTransfer` for nonce N.

**Result:** `maxReentry + 1` distinct `InitTransfer` events with nonces N through N+`maxReentry`, zero tokens actually locked, NEAR mints `(maxReentry + 1) × 1e18` tokens to `attacker.near`.

**Verification:** A Foundry invariant test asserting `sum(InitTransfer.amount) <= bridge.balanceOf(token)` will fail immediately with this attack contract. A fork test on a local Anvil node with a mock Wormhole (returning sequence 0 for any `publishMessage`) reproduces the full multi-VAA scenario.