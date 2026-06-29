Audit Report

## Title
`nativeFee` ETH Permanently Locked in `OmniBridgeWormhole` with No Withdrawal or Distribution Mechanism — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
In `OmniBridgeWormhole`, when `initTransfer` or `initTransfer1155` is called with a non-zero `nativeFee`, the ETH corresponding to `nativeFee` is silently retained in the contract. Only `extensionValue` (`msg.value − nativeFee`) is forwarded to the Wormhole core bridge. Neither `OmniBridge` nor `OmniBridgeWormhole` defines a `receive()`, `fallback()`, or any ETH-withdrawal function, so any ETH sent as `nativeFee` is permanently locked with no recovery path.

## Finding Description
In `OmniBridge.initTransfer` (L386–393), `extensionValue` is computed as:
- ERC-20: `extensionValue = msg.value - nativeFee`
- Native ETH: `extensionValue = msg.value - amount - nativeFee`

Only `extensionValue` is passed to `initTransferExtension` (L415–425). In `OmniBridgeWormhole.initTransferExtension` (L118–150), only `value` (i.e., `extensionValue`) is forwarded to Wormhole via `_wormhole.publishMessage{value: value}(...)` (L143). The `nativeFee` portion of `msg.value` is never forwarded, refunded, or transferred anywhere.

`TestWormhole.publishMessage` enforces `require(msg.value == this.messageFee(), "invalid fee")` (L13), so `extensionValue` must equal exactly `messageFee()` (10 000 wei). A user who sets `nativeFee = X` must send `msg.value = X + messageFee()`, and the `X` wei is irrecoverably retained by the contract.

A grep for `receive()`, `fallback()`, and `withdraw` across all EVM contract files confirms no such function exists in `OmniBridge.sol` or `OmniBridgeWormhole.sol`. The same pattern applies to `initTransfer1155` (L466): `extensionValue = msg.value - nativeFee`.

The contract imposes no upper bound and no enforcement of `nativeFee == 0`. The `nativeFee` field is a first-class parameter in the `InitTransfer` event (L427–436) and in the Wormhole cross-chain payload (L138), giving users a reasonable expectation that setting it non-zero has a meaningful effect.

## Impact Explanation
Any ETH sent as `nativeFee` is permanently locked inside `OmniBridgeWormhole` with no exit path. This constitutes a permanent loss of user funds on an EVM chain, matching the allowed critical impact: *"Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."* The loss is irreversible without a contract upgrade, and accumulates across all users who supply non-zero `nativeFee`.

## Likelihood Explanation
Any unprivileged bridge user can trigger this by calling `initTransfer` or `initTransfer1155` with `nativeFee > 0`. No special role, privilege, or external condition is required. The NEAR-side `native_token_fee` mechanic (where a non-zero value incentivises relayers) creates a natural expectation that the EVM-side `nativeFee` parameter works analogously. The contract provides no on-chain guard, revert, or documentation to prevent this. The exploit is repeatable by any user on every call.

## Recommendation
Choose one of:

1. **Enforce `nativeFee == 0` on EVM.** Add `if (nativeFee != 0) revert InvalidFee();` at the top of `initTransfer` and `initTransfer1155`, since relayer compensation on EVM-originated transfers is handled in NEAR tokens on the NEAR side.

2. **Refund `nativeFee` to `msg.sender`.** After `_wormhole.publishMessage` succeeds, return the `nativeFee` ETH to the caller.

3. **Route `nativeFee` to a designated relayer or fee-collector address.** If ETH-denominated relayer fees are intentional, add an explicit transfer of `nativeFee` within `initTransferExtension`.

## Proof of Concept
1. Deploy `OmniBridgeWormhole` with `TestWormhole` (messageFee = 10 000 wei).
2. Call:
   ```solidity
   OmniBridgeWormhole.initTransfer(
       erc20Token,
       1000,
       0,
       1 ether,        // nativeFee — non-zero
       "alice.near",
       "",
       { value: 1 ether + 10_000 }
   );
   ```
3. Inside `initTransfer`: `extensionValue = (1 ether + 10_000) − 1 ether = 10_000`.
4. `initTransferExtension` calls `_wormhole.publishMessage{value: 10_000}(...)` — succeeds (exact fee match).
5. `1 ether` remains in `OmniBridgeWormhole`. No function exists to withdraw it.
6. The `InitTransfer` event is emitted; the NEAR relayer is paid in NEAR tokens. The 1 ETH is permanently locked.

Verify with a Hardhat test asserting `ethers.provider.getBalance(OmniBridgeWormhole.address)` equals `1 ether` after the call, and that no withdrawal function exists to recover it.