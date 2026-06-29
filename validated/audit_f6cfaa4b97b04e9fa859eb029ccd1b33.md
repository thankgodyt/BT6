Audit Report

## Title
Reentrancy via ERC777 `tokensToSend` hook causes nonce collision and permanent fund loss - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary
`OmniBridge.initTransfer` increments `currentOriginNonce` before the external token call but reads the storage variable again after the call to populate `initTransferExtension` and emit `InitTransfer`. An ERC777 token's `tokensToSend` hook fires on the sender during `safeTransferFrom`, allowing an attacker to reenter `initTransfer`, increment the nonce a second time, and cause both the inner and outer calls to emit `InitTransfer` with the same nonce. The outer transfer's original nonce is never emitted, permanently locking those tokens in the bridge with no NEAR-side finalization path.

## Finding Description
In `OmniBridge.initTransfer` (lines 373–437), the execution order is:

1. **Line 381**: `currentOriginNonce += 1` — nonce incremented to N.
2. **Lines 407–411**: `IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount)` — for a non-bridge, non-custom-minter token, this external call fires the ERC777 `tokensToSend` hook on the sender's registered ERC1820 implementer.
3. Inside the hook, the attacker reenters `initTransfer`:
   - Line 381 again: `currentOriginNonce += 1` — nonce becomes N+1.
   - Inner `safeTransferFrom` completes (hook not registered for second call).
   - Lines 415–425: `initTransferExtension(..., currentOriginNonce=N+1, ...)`.
   - Lines 427–436: `emit InitTransfer(..., currentOriginNonce=N+1, ...)` — inner event emitted with nonce N+1.
4. Outer call resumes after the external call returns.
5. Lines 415–425: `initTransferExtension(..., currentOriginNonce=N+1, ...)` — reads the now-mutated storage value N+1.
6. Lines 427–436: `emit InitTransfer(..., currentOriginNonce=N+1, ...)` — outer event also emitted with nonce N+1.

No `ReentrancyGuardUpgradeable` is imported or applied anywhere in the EVM contracts (confirmed: zero matches for `ReentrancyGuard`/`nonReentrant` in `evm/src/`). The contract inherits only `UUPSUpgradeable`, `AccessControlUpgradeable`, `SelectivePausableUpgradable`, and `IERC1155Receiver`. The `whenNotPaused` modifier provides no reentrancy protection.

The root cause is that the nonce is snapshotted implicitly by incrementing storage, but the post-increment storage value is re-read after the external call rather than using a local variable captured before the call. This violates the documented invariant in `evm/CLAUDE.md` (line 34): "Always mutate state (e.g. mark nonce used) before any external call" — the nonce is mutated before the call, but it is read again after, breaking the invariant under reentrancy.

The same structural flaw exists in `initTransfer1155` (lines 447–490): `currentOriginNonce += 1` at line 448, then `IERC1155.safeTransferFrom` at lines 458–464, then `currentOriginNonce` re-read at lines 471 and 483. A malicious ERC1155 token with custom `safeTransferFrom` logic can exploit the same pattern.

## Impact Explanation
- **Nonce N** (the outer call's intended nonce) is never emitted in any `InitTransfer` event. The outer transfer's tokens are locked in the bridge contract with no corresponding NEAR-side event to process.
- **Nonce N+1** is emitted twice — once by the inner call and once by the outer call. The NEAR side processes the first occurrence and rejects the second as a replay.
- The outer transfer's tokens are **permanently frozen** in the bridge contract: the NEAR side will never finalize a transfer for nonce N (no event exists) and will reject nonce N+1 as a duplicate. There is no recovery path.

This matches the critical allowed impact: **permanent freezing of bridged funds** and **nonce/replay misuse that changes user balances**.

## Likelihood Explanation
ERC777 tokens are backward-compatible with ERC20 and are deployed on Ethereum mainnet (e.g., imBTC, LUKSO LYX). `initTransfer` accepts any `tokenAddress` with no whitelist check — the non-bridge, non-custom-minter path is taken for any token not in `isBridgeToken` or `customMinters`. An attacker can:
1. Deploy or use an existing ERC777 token.
2. Register their own address as the `ERC777TokensSender` implementer via the ERC1820 registry.
3. Call `initTransfer` with that token; the `tokensToSend` hook fires during `safeTransferFrom` and reenters `initTransfer` with a second transfer.

No admin privileges are required. The attack is repeatable and unprivileged.

## Recommendation
1. **Snapshot the nonce into a local variable before any external call** and use only the local variable in `initTransferExtension` and `emit`:
   ```solidity
   uint64 originNonce = currentOriginNonce + 1;
   currentOriginNonce = originNonce;
   // ... external calls ...
   initTransferExtension(..., originNonce, ...);
   emit BridgeTypes.InitTransfer(..., originNonce, ...);
   ```
2. **Add `ReentrancyGuardUpgradeable`** and apply `nonReentrant` to both `initTransfer` and `initTransfer1155` as defense-in-depth.
3. Apply the same local-variable snapshot fix to `initTransfer1155`.

## Proof of Concept
```
State: currentOriginNonce = 5

1. Attacker calls initTransfer(erc777Token, amount1, ...)
   → currentOriginNonce = 6                          [line 381]
   → safeTransferFrom fires tokensToSend on attacker [lines 407-411]

2. Attacker's hook calls initTransfer(erc777Token, amount2, ...)
   → currentOriginNonce = 7                          [line 381]
   → safeTransferFrom completes (no hook this time)
   → initTransferExtension(..., nonce=7, ...)         [line 418: reads storage=7]
   → emit InitTransfer(nonce=7, amount=amount2)       [line 430: reads storage=7]

3. Outer call resumes
   → initTransferExtension(..., nonce=7, ...)         [line 418: reads storage=7]
   → emit InitTransfer(nonce=7, amount=amount1)       [line 430: reads storage=7]

Result:
- Two InitTransfer events with nonce 7 on EVM
- Nonce 6 never emitted → amount1 tokens permanently locked
- NEAR processes nonce 7 once (amount2), rejects second nonce 7 as replay
```

A Foundry test can reproduce this by deploying a mock ERC777 token whose `transferFrom` calls back into `OmniBridge.initTransfer` before returning, then asserting that two `InitTransfer` events share the same nonce and that nonce 6 is absent from all emitted events.