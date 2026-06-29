Audit Report

## Title
No-Recovery Path for Failed Native-ETH `finTransfer` Permanently Locks Bridged Funds — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
In `OmniBridge.sol`, `finTransfer` marks the destination nonce as consumed before attempting ETH delivery. If the low-level ETH `call` to the recipient fails, `revert FailedToSendEther()` rolls back the entire transaction — including the nonce marking — leaving the nonce unconsumed and the transfer permanently unfinalizeable. Because the corresponding wrapped-ETH tokens are burned on NEAR at initiation time and no public cancellation path exists on NEAR, the user's funds are permanently frozen.

## Finding Description
In `finTransfer`, the nonce is marked used at line 287, before the ETH delivery attempt:

```solidity
completedTransfers[payload.destinationNonce] = true;   // L287
``` [1](#0-0) 

Then, for native ETH transfers (`payload.tokenAddress == address(0)`), the contract attempts a low-level call:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();   // L322
``` [2](#0-1) 

Because `revert` rolls back all state changes in the transaction, `completedTransfers[payload.destinationNonce] = true` is also rolled back. The nonce is never consumed, so any relayer can retry — but every retry produces the same revert if the recipient contract lacks `receive()` or `fallback()`.

On the NEAR side, `init_transfer_internal` burns or locks the wrapped-ETH tokens and returns `U128(0)` (no refund to the caller):

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(...);
// ...
U128(0)
``` [3](#0-2) 

The internal `remove_transfer_message` function is the only mechanism to remove a pending transfer entry and refund storage, but it is a private `fn` — not `pub fn` — and is only called on successful finalization or a storage-check failure during initiation: [4](#0-3) 

A grep across the entire NEAR bridge codebase confirms there is no public `cancel_transfer`, `cancel_pending`, or equivalent function exposed to users or admins.

## Impact Explanation
This matches the allowed critical impact: **permanent freezing of bridged funds**. The wrapped-ETH tokens are burned on NEAR at initiation; the EVM `finTransfer` can never succeed for an ETH-rejecting recipient; and there is no on-chain path — on either chain — to reclaim the funds. The loss is irreversible.

## Likelihood Explanation
Many deployed smart contracts — Gnosis Safes (without ETH receipt enabled), DAO governance contracts, pure-logic vaults — intentionally omit `receive()` / `fallback()`. A user bridging native ETH to any such address triggers this condition through ordinary usage of the public `ft_transfer_call` entry point on NEAR. No privileged access or malicious intent is required; the user simply specifies a contract address as the EVM recipient.

## Recommendation
Two viable fixes:

1. **Recovery address in payload**: Accept an optional `recovery` address in `InitTransferMsg`. If `finTransfer` fails for native ETH (or ERC-1155), route funds to the recovery address instead of reverting.
2. **NEAR-side cancellation**: Expose a public `cancel_transfer` function on NEAR (with a timeout guard, e.g., after N blocks/epochs with no successful finalization) that calls `remove_transfer_message` and refunds the burned/locked tokens to the original sender.

Either fix must be applied consistently to both the native-ETH path and the ERC-1155 `safeTransferFrom` path, which has the same revert-loop behavior.

## Proof of Concept
1. User holds wrapped-ETH on NEAR and calls `ft_transfer_call` targeting the NEAR bridge, with `recipient = OmniAddress::Eth(<GnosisSafe address>)` where the Safe has no `receive()`.
2. `init_transfer_internal` burns the wrapped-ETH and stores the `TransferMessage` in `pending_transfers`. Returns `U128(0)` — no refund.
3. MPC signs the transfer; a relayer calls `finTransfer` on EVM with `payload.tokenAddress == address(0)` and `payload.recipient = <GnosisSafe address>`.
4. `payload.recipient.call{value: payload.amount}("")` returns `success = false`.
5. `revert FailedToSendEther()` rolls back the transaction, including `completedTransfers[nonce] = true`.
6. Every subsequent relay attempt produces the same revert.
7. The wrapped-ETH is permanently burned on NEAR; no recovery path exists on either chain.

To reproduce locally: deploy a minimal contract without `receive()` as the EVM recipient, run the NEAR → EVM transfer flow in a local testnet, and confirm that `finTransfer` always reverts and the NEAR-side `pending_transfers` entry is never removed.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
```

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
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
```
