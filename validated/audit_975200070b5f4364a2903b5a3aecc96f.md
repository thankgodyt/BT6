Looking at the actual code to verify the claim precisely.

Key observations from `OmniBridge.sol`:

1. In `initTransfer` for ERC20 tokens: `extensionValue = msg.value - nativeFee` (L393) — the `nativeFee` portion is subtracted and stays in the contract.
2. In `OmniBridgeWormhole.sol::initTransferExtension` (L143): `_wormhole.publishMessage{value: value}(...)` — only `extensionValue` (the Wormhole message fee) is forwarded; `nativeFee` is never forwarded anywhere.
3. The base `initTransferExtension` (L503) reverts if `value != 0`, confirming `extensionValue` must be zero in the non-Wormhole deployment, meaning `msg.value == nativeFee` exactly — all ETH stays in the contract.
4. No `withdraw`, `rescue`, or fee-distribution function exists anywhere in the contract surface.
5. The only ETH egress is `finTransfer` (L319) for native-ETH bridge transfers, which is unrelated to accumulated `nativeFee` ETH.
6. `receive() external payable {}` (L574) accepts ETH but provides no egress path.

The claim is accurate and the impact (fee mis-accounting / permanent freezing of user-paid ETH) matches the allowed scope.

---

Audit Report

## Title
`nativeFee` ETH Permanently Trapped With No Distribution or Recovery Path — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
Every call to `initTransfer` or `initTransfer1155` that includes a non-zero `nativeFee` causes the corresponding ETH to be permanently locked in the bridge contract. No function exists to forward, distribute, or recover this ETH. The design intent — paying the relayer — is fulfilled on the NEAR side but silently broken on the EVM side, resulting in irreversible loss of user funds on every ERC20 bridge transfer that pays a fee.

## Finding Description
In `OmniBridge.sol::initTransfer`, when `tokenAddress != address(0)` (ERC20 path):

```solidity
extensionValue = msg.value - nativeFee;   // L393
```

`extensionValue` is passed to `initTransferExtension`. In `OmniBridgeWormhole`, this extension forwards only `extensionValue` to Wormhole:

```solidity
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);  // L143
```

The `nativeFee` portion of `msg.value` is never forwarded. It remains in the contract balance. In the base `OmniBridge` (non-Wormhole) deployment, `initTransferExtension` reverts if `value != 0` (L503), so `msg.value` must equal `nativeFee` exactly — meaning 100% of the ETH sent stays in the contract.

The only ETH egress path is `finTransfer` (L317–322), which sends `payload.amount` to the recipient for native-ETH bridge transfers — a completely separate accounting pool. There is no `withdraw`, `rescue`, or fee-forwarding function anywhere in the contract. The `receive()` fallback (L574) accepts ETH but provides no egress.

On the NEAR side, `send_fee_internal` correctly transfers `native_fee` to the fee recipient via `Promise::new(fee_recipient).transfer(...)`. The EVM side has no equivalent, confirming this is an implementation gap, not a design choice.

## Impact Explanation
Every user who pays a non-zero `nativeFee` when calling `initTransfer` for an ERC20 token permanently loses that ETH. The ETH accumulates in the bridge contract with no recovery path. This constitutes fee mis-accounting and permanent freezing of user-paid funds, matching the Critical allowed impact: *"fee mis-accounting … that changes user or protocol balances"* and *"permanent freezing of bridged funds."*

## Likelihood Explanation
`nativeFee` is a first-class public ABI parameter. The README documents that standard relayers charge non-zero fees (custom relayers are noted as the zero-fee alternative), meaning any user relying on the standard relayer will pay a non-zero `nativeFee`. The condition is triggered on every such ERC20 `initTransfer` call with no special preconditions. Any unprivileged external user can trigger this by calling `initTransfer` with `msg.value = nativeFee > 0`.

## Recommendation
Forward `nativeFee` to a configurable fee recipient inside `initTransfer` immediately after computing `extensionValue`:

```solidity
if (nativeFee > 0) {
    (bool ok, ) = feeRecipient.call{value: nativeFee}("");
    if (!ok) revert FeeTransferFailed();
}
```

Alternatively, add an admin-controlled sweep function. The fee recipient address should be settable by `DEFAULT_ADMIN_ROLE` and stored in contract storage, mirroring the NEAR-side `fee_recipient` pattern.

## Proof of Concept
1. Deploy `OmniBridge` (or `OmniBridgeWormhole`) and register a standard ERC20 token.
2. Call `initTransfer(usdcAddress, 1000e6, 0, 0.01 ether, "recipient.near", "")` with `msg.value = 0.01 ether`.
3. Observe: `extensionValue = 0`, `initTransferExtension` passes, USDC is pulled, `InitTransfer` event emitted with `nativeFee = 0.01 ether`.
4. Check `address(bridge).balance` — it has increased by `0.01 ether`.
5. Attempt any function to recover the ETH — none exists.
6. Repeat for N users; `address(bridge).balance` grows by `N * nativeFee` with no recovery path.
7. Confirm via invariant test: `assert(bridge.balance == 0)` after all `initTransfer` calls with `nativeFee > 0` — invariant will always fail.