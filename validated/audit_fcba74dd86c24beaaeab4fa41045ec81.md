Audit Report

## Title
Malicious ERC20 Blacklist Causes Permanent Loss of Bridged Funds on NEAR→EVM Path - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

A malicious ERC20 token deployer can lock tokens in the bridge, receive NEAR-side bridge tokens, sell them to victims, then blacklist the bridge contract address in the token. When victims attempt to bridge back (NEAR→EVM), their NEAR bridge tokens are burned irreversibly in `init_transfer_internal`, but `finTransfer` on EVM always reverts because `safeTransfer` from the bridge to the recipient fails. No refund path exists on NEAR, resulting in permanent loss of bridged funds.

## Finding Description

The bridge is explicitly designed to be fully permissionless. `logMetadata` accepts any ERC20 address with no access control, and `initTransfer` accepts any token address with no whitelist check, as confirmed by `evm/SECURITY.md` line 8.

In `finTransfer`, for native (non-bridge-deployed) ERC20 tokens, the contract executes:

```solidity
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount
);
```

(`OmniBridge.sol`, lines 351–354)

If the token implements a blacklist on the `from` address and the attacker blacklists the bridge contract itself, this `safeTransfer` (which sends FROM the bridge TO the recipient) will always revert. Because the entire `finTransfer` transaction reverts, the `completedTransfers[payload.destinationNonce]` state change (line 287) is also reverted — the nonce is not permanently consumed. However, on the NEAR side, the bridge tokens were already burned in `init_transfer_internal` before `finTransfer` was ever called:

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
```

(`near/omni-bridge/src/lib.rs`, lines 1850–1851)

The transfer message is stored in `pending_transfers` (line 1835), but no public function exists to cancel or refund a pending transfer. `remove_transfer_message` (lines 2194–2211) is an internal function called only on successful finalization paths, not on EVM-side failure. There is no cross-chain callback from EVM to NEAR that signals a failed `finTransfer`. The relayer will retry indefinitely, but every attempt will revert, and the burned NEAR tokens are unrecoverable.

## Impact Explanation

This is a concrete instance of **permanent freezing of bridged funds across NEAR and EVM**: the victim's NEAR-side bridge tokens are burned with no recovery path, and the corresponding EVM-side tokens remain locked in the bridge contract forever. The attacker profits by selling NEAR bridge tokens that are backed by an unwithdrawable EVM position. This matches the critical impact category exactly.

## Likelihood Explanation

The attack requires only unprivileged actions:
1. Deploy a malicious ERC20 with a `from`-address blacklist (trivial, no permission needed).
2. Call `OmniBridge.logMetadata(maliciousToken)` — permissionless by design.
3. Call `OmniBridge.initTransfer(maliciousToken, amount, ...)` — tokens locked in bridge, NEAR bridge tokens minted to attacker.
4. Sell NEAR bridge tokens to victims via a DEX.
5. Call `setBlacklist(bridgeAddress)` on the malicious token.

All five steps are unprivileged. The attack is repeatable across any number of victims and any EVM chain where the bridge is deployed.

## Recommendation

Two mitigations should be considered together:

1. **Wrap `safeTransfer` in a try/catch in `finTransfer`**: On failure, emit a `FailedFinTransfer` event and do not consume the nonce. The NEAR side should implement a `cancel_transfer` callback that, upon receiving a signed `FailedFinTransfer` proof, re-mints the burned tokens to the original sender.

2. **Alternatively, implement a token allowlist**: Restrict `initTransfer` and `logMetadata` to admin-approved ERC20 addresses. This is a stronger fix but sacrifices the permissionless design goal.

The try/catch approach preserves permissionlessness while closing the fund-loss vector.

## Proof of Concept

**Attack sequence:**

1. Attacker deploys `MaliciousToken` (ERC20 with `_beforeTokenTransfer` that reverts if `from == blacklistedAddress`).
2. Attacker calls `OmniBridge.logMetadata(maliciousToken)` — succeeds, no access control (`OmniBridge.sol` lines 224–232).
3. Attacker calls `OmniBridge.initTransfer(maliciousToken, amount, ...)` — `safeTransferFrom` pulls tokens from attacker into bridge (`OmniBridge.sol` lines 407–411); `InitTransfer` event emitted.
4. NEAR relayer observes event, mints NEAR bridge tokens to attacker. Attacker sells them to victim on a DEX.
5. Attacker calls `maliciousToken.setBlacklist(bridgeAddress)`.
6. Victim calls `ft_transfer_call` on NEAR bridge token → `ft_on_transfer` → `init_transfer_internal` → `burn_tokens_if_needed` burns victim's NEAR tokens (`near/omni-bridge/src/lib.rs` line 1851). Transfer stored in `pending_transfers`.
7. Relayer calls `OmniBridge.finTransfer(sig, payload)` on EVM. Execution reaches `IERC20(maliciousToken).safeTransfer(victim, amount)` (`OmniBridge.sol` lines 351–354) — **reverts** because bridge address is blacklisted.
8. Entire EVM transaction reverts. Nonce not consumed. Victim's NEAR tokens are permanently gone. EVM tokens remain locked in bridge. No refund path exists on NEAR (`near/omni-bridge/src/lib.rs` lines 2194–2224 show `remove_transfer_message` is internal-only with no public cancel entrypoint). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-355)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/lib.rs (L2194-2224)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }

    fn remove_transfer_message_without_refund(
        &mut self,
        transfer_id: TransferId,
    ) -> TransferMessage {
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        transfer.message
    }
```

**File:** evm/SECURITY.md (L8-8)
```markdown
- **`logMetadata` and `deployToken` are permissionless**: Anyone can call `logMetadata` for any ERC20, and anyone can submit a valid MPC signature to `deployToken`. This is by design — the bridge is fully permissionless
```
