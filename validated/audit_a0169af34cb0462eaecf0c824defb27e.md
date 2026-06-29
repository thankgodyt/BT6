Audit Report

## Title
Native ETH delivery via raw `.call` permanently freezes bridged funds when recipient contract rejects ETH — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
In `OmniBridge.finTransfer`, native ETH is delivered to the recipient via a raw low-level `.call`. If the recipient is a contract without a `receive()` / `fallback()` function, or one whose `receive()` reverts, the entire transaction reverts. Because the recipient address is cryptographically bound inside the MPC-signed borsh payload and cannot be substituted, every relay attempt will revert indefinitely. The corresponding NEAR-side transfer message has no user-accessible cancellation or refund path, permanently freezing the bridged funds.

## Finding Description
In `finTransfer` (lines 279–367 of `OmniBridge.sol`), the nonce is marked consumed at line 287 before the asset dispatch:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287
```

For native ETH (`payload.tokenAddress == address(0)`), the dispatch is (lines 317–322):

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();
```

When `FailedToSendEther` is thrown, the entire transaction reverts, rolling back the `completedTransfers` write. The nonce is therefore never permanently consumed, so relayers can retry — but the recipient is encoded inside the MPC-signed borsh blob (line 298: `Borsh.encodeAddress(payload.recipient)`) and verified at lines 309–313. No alternative recipient can be supplied.

On the NEAR side, `sign_transfer_callback` (lines 648–668 of `near/omni-bridge/src/lib.rs`) removes the transfer message only when `fee.is_zero()` (line 656–658). For non-zero-fee transfers the message stays in `pending_transfers`. The only other removal path is `claim_fee_callback` (line 1094), which requires a `ProverResult::FinTransfer` proof — i.e., proof that `finTransfer` succeeded on EVM. Since `finTransfer` always reverts, this proof can never be produced. No public, user-callable cancel or refund function exists in the contract.

## Impact Explanation
This directly satisfies the allowed critical impact: **permanent freezing of bridged funds**. The source-chain tokens (locked or burned on NEAR) can never be released because `finTransfer` will always revert for a rejecting-contract recipient, and no on-chain mechanism exists to cancel the pending transfer message and refund the sender. The funds are irrecoverable without a contract upgrade.

## Likelihood Explanation
The scenario is reachable by any unprivileged bridge user through normal bridge flows:

1. **Accidental (primary path):** A user bridges native ETH to a DeFi contract (vault, multisig, proxy, or any contract that intentionally lacks `receive()` to prevent accidental ETH sends). This is a common and expected contract pattern. The user reasonably expects the bridge to handle delivery gracefully (e.g., by wrapping as WETH), not to permanently freeze their funds.
2. **Intentional grief:** A malicious recipient deploys a contract that initially accepts ETH, lures a sender into bridging to it, then upgrades or self-destructs and redeploys to reject ETH before the relayer calls `finTransfer`. The sender's funds are permanently locked with no recovery path.

No admin escape hatch exists: there is no DAO or operator function visible in the contract to forcibly cancel a stuck transfer.

## Recommendation
Wrap native ETH as WETH before delivering it to the recipient, eliminating the recipient's ability to reject the transfer:

```solidity
if (payload.tokenAddress == address(0)) {
    IWETH(wethAddress).deposit{value: payload.amount}();
    IERC20(wethAddress).safeTransfer(payload.recipient, payload.amount);
}
```

Alternatively, implement a pull-payment pattern: on ETH delivery failure, credit the recipient's claimable balance and allow them to withdraw later, so a single bad recipient cannot permanently lock source-chain funds.

## Proof of Concept
1. Deploy a rejecting contract on the target EVM chain:
   ```solidity
   contract Rejecter {
       receive() external payable { revert("no ETH"); }
   }
   ```
2. On NEAR, call `ft_on_transfer` with an `InitTransferMsg` specifying `recipient = OmniAddress::Eth(address(Rejecter))` and any amount of the ETH-bridged token.
3. NEAR locks/burns the tokens and stores the transfer message via `add_transfer_message`.
4. A relayer calls `sign_transfer`; the MPC network signs the payload; `sign_transfer_callback` is invoked. If fee is zero, the transfer message is removed (tokens permanently lost). If fee is non-zero, the message stays in `pending_transfers`.
5. Any relayer calls `OmniBridge.finTransfer` on EVM. The `.call` to `Rejecter.receive()` reverts → `FailedToSendEther` → entire tx reverts → nonce rolled back.
6. Every subsequent relay attempt reverts identically.
7. `claim_fee_callback` on NEAR requires a proof of EVM finalization that can never be produced. The NEAR transfer message is never removed; the user's funds are permanently frozen.