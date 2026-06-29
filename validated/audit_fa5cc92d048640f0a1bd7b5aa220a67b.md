Audit Report

## Title
`nativeFee` ETH Permanently Locked With No Withdrawal Mechanism - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
Both `initTransfer` and `initTransfer1155` are `payable` and accept ETH from callers as `nativeFee`. In `OmniBridge`, the base `initTransferExtension` reverts unless `extensionValue == 0`, meaning `msg.value` must equal exactly `nativeFee` (ERC-20 path) or `amount + nativeFee` (native ETH path). In `OmniBridgeWormhole`, only `extensionValue` (i.e., `msg.value - nativeFee`) is forwarded to Wormhole via `publishMessage`; the `nativeFee` portion is never forwarded. No function in either contract allows any party to withdraw or forward the accumulated `nativeFee` ETH, permanently locking it in the contract.

## Finding Description
In `OmniBridge.initTransfer` (L386–413), `extensionValue` is computed as `msg.value - nativeFee` (ERC-20) or `msg.value - amount - nativeFee` (native ETH). `initTransferExtension` is called with this `extensionValue`. The base implementation at L492–506 reverts if `value != 0`, so for the base contract `extensionValue` must be zero, meaning the entire `msg.value` equals `nativeFee` (ERC-20) or `amount + nativeFee` (native ETH) — all of which stays in the contract.

In `OmniBridgeWormhole.initTransferExtension` (L118–150), only `value` (= `extensionValue`) is forwarded to `_wormhole.publishMessage{value: value}(...)`. The `nativeFee` portion is encoded into the Wormhole payload as a cross-chain signal but the corresponding ETH is never sent anywhere — it remains in the contract.

`initTransfer1155` (L466) follows the identical pattern: `extensionValue = msg.value - nativeFee`, with `nativeFee` ETH retained.

A full audit of `OmniBridge.sol` confirms no `withdraw`, `rescueETH`, or any admin function that moves ETH out. The only ETH egress is `finTransfer` (L317–322) sending `payload.amount` to a recipient for native ETH bridging — unrelated to `nativeFee` balances. The bare `receive()` at L574 confirms the contract is designed to hold ETH, with no corresponding egress for `nativeFee`.

## Impact Explanation
Every user who calls `initTransfer` or `initTransfer1155` with `nativeFee > 0` permanently loses that ETH. The funds accumulate in the contract and are irrecoverable by any party — no admin, relayer, or user can retrieve them through any currently deployed function. This constitutes permanent freezing of user funds on the EVM side of the bridge, matching the "permanent freezing of bridged funds across EVM or Wormhole-routed flows" critical impact class.

## Likelihood Explanation
High. `nativeFee` is a documented, first-class parameter of the public `initTransfer` API. Any user following the documented bridge flow who sets a non-zero `nativeFee` to incentivize a relayer will have that ETH permanently locked. This occurs during normal, intended operation of the bridge with no special preconditions. The exploit is repeatable on every call with `nativeFee > 0`.

## Recommendation
Add a mechanism to forward or withdraw the `nativeFee` ETH. The preferred fix is to forward `nativeFee` directly to a designated relayer fee recipient at call time within `initTransferExtension`, ensuring relayers are compensated atomically:

```solidity
if (nativeFee > 0) {
    (bool ok, ) = feeRecipient.call{value: nativeFee}("");
    require(ok, "NativeFee transfer failed");
}
```

Alternatively, add an admin rescue function:

```solidity
function withdrawNativeFees(address payable recipient, uint256 amount)
    external onlyRole(DEFAULT_ADMIN_ROLE)
{
    (bool ok, ) = recipient.call{value: amount}("");
    require(ok, "Withdraw failed");
}
```

## Proof of Concept
1. User calls `initTransfer(tokenAddress, amount, fee, 1 ether, "recipient.near", "")` with `msg.value = 1 ether` (ERC-20 path, `nativeFee = 1 ether`).
2. `extensionValue = 1 ether - 1 ether = 0`. Base `OmniBridge.initTransferExtension` does not revert.
3. `initTransferExtension` is called with `value = 0` — no ETH is forwarded anywhere.
4. `InitTransfer` event is emitted with `nativeFee = 1 ether` as a cross-chain signal only.
5. `address(OmniBridge).balance` increases by `1 ether`.
6. No function in the contract can retrieve this ETH. It is permanently locked.

For `OmniBridgeWormhole`: user calls with `msg.value = wormholeFee + nativeFee`. Only `wormholeFee` is forwarded to `_wormhole.publishMessage`; `nativeFee` ETH remains locked identically.