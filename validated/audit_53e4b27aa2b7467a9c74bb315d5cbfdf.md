Audit Report

## Title
`initTransfer` Locks Unregistered ERC20 Tokens With No Recovery Path — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`OmniBridge.sol::initTransfer` performs no registration check before locking native ERC20 tokens into the contract. Any token that is neither a bridge-deployed token (`isBridgeToken`) nor a custom-minter token falls into the `else` branch and is transferred to the contract. If the token has no corresponding `token_decimals` entry on NEAR, `fin_transfer_callback` panics with `BridgeError::TokenDecimalsNotFound`, the cross-chain transfer is never finalized, and the locked tokens are permanently irrecoverable because no admin sweep or emergency-withdrawal function exists in the contract.

## Finding Description

In `initTransfer` (lines 373–437), the ERC20 handling logic is:

```
customMinters[tokenAddress] != address(0)  → burn via custom minter
isBridgeToken[tokenAddress]                → burn bridge token
else                                       → safeTransferFrom(msg.sender, address(this), amount)
```

The `else` branch (lines 406–411) performs no check that the token is registered anywhere. Critically, `logMetadata` (lines 224–232) does **not** set `ethToNearToken` — it only emits an event and calls the no-op virtual `logMetadataExtension`. The `ethToNearToken` mapping is only populated by `addCustomToken` (line 95) and `deployToken` (line 191). For all native ERC20 tokens, `ethToNearToken[tokenAddress]` is always empty on the EVM side; registration exists solely in NEAR's `token_decimals` storage.

After `removeCustomToken` (lines 120–127) is called, `isBridgeToken`, `ethToNearToken`, `nearToEthToken`, and `customMinters` are all deleted for that token. A subsequent `initTransfer` call for that token silently falls into the `else` branch and locks the tokens.

On the NEAR side, `fin_transfer_callback` (lines 715–718) immediately calls:
```rust
let decimals = self
    .token_decimals
    .get(&init_transfer.token)
    .near_expect(BridgeError::TokenDecimalsNotFound);
```
This panics if the token was never registered or was de-registered. The panic reverts all NEAR-side state changes but does not trigger any EVM-side refund. A search of the EVM contracts confirms no `emergencyWithdraw`, `sweep`, `rescueToken`, or equivalent function exists. The `revert_transfer` mechanism found in NEAR-side code (`near/omni-bridge/src/token_lock.rs`) is a NEAR-internal flow and cannot unlock EVM-side tokens when the NEAR transaction itself panics before producing any provable state.

## Impact Explanation

Permanent freezing of bridged funds. Any user who calls `initTransfer` with a native ERC20 token that lacks a `token_decimals` entry on NEAR will have their tokens locked in `OmniBridge` with no on-chain recovery path. This matches the Critical impact class: "permanent freezing of bridged funds across EVM flows."

## Likelihood Explanation

The function is fully public and requires no special role. The most realistic trigger is the `removeCustomToken` admin action: after a token is de-listed, users who are unaware continue to call `initTransfer` and lose funds. A second realistic trigger is calling `initTransfer` after `logMetadata` but before NEAR-side `token_decimals` registration completes — the EVM side has no way to detect this race condition. No attacker capability or privileged access is required; any token holder can trigger this unintentionally.

## Recommendation

Add a registration guard at the top of `initTransfer` before any token transfer occurs. Because `ethToNearToken` is not set for native ERC20 tokens, the guard must rely on a separate allowlist or on the NEAR-side registration being mirrored to the EVM side. The minimal fix is to maintain an explicit `registeredTokens` mapping updated by `logMetadata` and cleared by a corresponding de-registration function, and require membership before accepting any transfer:

```solidity
require(
    tokenAddress == address(0) ||
    isBridgeToken[tokenAddress] ||
    customMinters[tokenAddress] != address(0) ||
    registeredTokens[tokenAddress],
    "ERR_TOKEN_NOT_REGISTERED"
);
```

Apply the same guard to `initTransfer1155` before the `safeTransferFrom` call (line 458), checking `multiTokens[deterministicToken].tokenAddress != address(0)`.

## Proof of Concept

1. Deploy any ERC20 token `T` not registered via `deployToken`/`addCustomToken`, or call `removeCustomToken(T)` on a previously registered token.
2. Confirm: `isBridgeToken[T] == false`, `customMinters[T] == address(0)`, `ethToNearToken[T] == ""`.
3. Approve `OmniBridge` to spend `T`.
4. Call `OmniBridge.initTransfer(T, amount, 0, 0, "<valid-near-recipient>", "")`.
5. `safeTransferFrom` succeeds; `amount` of `T` is now held by `OmniBridge`. `InitTransfer` event is emitted.
6. A relayer submits the proof to NEAR `fin_transfer`.
7. `fin_transfer_callback` panics: `token_decimals.get(&init_transfer.token)` returns `None` → `BridgeError::TokenDecimalsNotFound`. NEAR transaction reverts.
8. No EVM-side refund is triggered. `T` tokens remain locked in `OmniBridge` permanently. No admin function exists to recover them.