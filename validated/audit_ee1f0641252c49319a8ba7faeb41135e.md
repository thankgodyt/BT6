### Title
Blacklisted ERC-20 Recipient Permanently Freezes Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`finTransfer` in `OmniBridge.sol` transfers tokens directly to `payload.recipient` in a single atomic transaction. When the destination token has a blacklist (e.g., USDC, USDT), a blacklisted recipient causes every `finTransfer` call to revert. Because the NEAR side has already burned or locked the tokens during `init_transfer`, and there is no cancellation or refund path on either side, the bridged funds are permanently frozen.

---

### Finding Description

**Root cause — `OmniBridge.sol` `finTransfer`:**

`completedTransfers[payload.destinationNonce]` is set to `true` at line 287, before any token movement. If the subsequent `safeTransfer` (or `mint`) reverts, the EVM runtime rolls back the entire transaction, including the nonce flag. The nonce is therefore never consumed, so the relayer can retry — but every retry will revert for the same reason. [1](#0-0) 

The token delivery path for a plain ERC-20 (e.g., USDC held in the bridge vault): [2](#0-1) 

If `payload.recipient` is on the USDC blacklist, `safeTransfer` reverts unconditionally. There is no fallback branch, no escrow, and no alternative recipient.

**Source-side state is already committed — NEAR `init_transfer_internal`:**

When the user initiates the outbound transfer on NEAR, `init_transfer_internal` burns bridged tokens (or increments the locked-token counter) and emits `InitTransferEvent` before the relayer ever touches the EVM side. [3](#0-2) 

Once that event is emitted, the NEAR contract has no public `cancel_transfer`, `refund_transfer`, or emergency-recovery function — confirmed by a full search of `near/omni-bridge/src/lib.rs`. The only internal helpers that remove a pending transfer (`remove_transfer_message`, `remove_transfer_message_without_refund`) are never exposed as callable entry points. [4](#0-3) 

**Result:** the EVM nonce is never consumed (every `finTransfer` reverts), the NEAR tokens are already burned/locked, and there is no path to recover them. The transfer is permanently stuck.

---

### Impact Explanation

Permanent freezing of bridged funds. Tokens burned or locked on NEAR can never be delivered to the EVM recipient and cannot be reclaimed by the sender. This matches the allowed critical impact: *"permanent freezing of bridged funds across NEAR, EVM … flows."*

The Starknet `fin_transfer` has an identical structure (`_set_transfer_finalised` before `transfer`, with `assert(success, 'ERR_TRANSFER_FAILED')` reverting the whole call), so the same freeze applies to Starknet-bound transfers. [5](#0-4) 

---

### Likelihood Explanation

USDC and USDT — both of which implement address blacklists — are primary bridging targets on every supported EVM chain (Ethereum, Arbitrum, Base, Polygon). A recipient can be blacklisted by Circle/Tether at any time after the user submits `init_transfer` on NEAR but before the relayer finalises on EVM. The scenario requires no privileged access: any ordinary user who sends to an address that later becomes blacklisted (e.g., due to sanctions, exchange compliance, or a compromised wallet) triggers the freeze.

---

### Recommendation

Replace the direct-push delivery in `finTransfer` with a pull pattern:

1. Instead of calling `safeTransfer(payload.recipient, payload.amount)` directly, credit the amount to a per-recipient claimable balance mapping inside the bridge contract.
2. Expose a separate `claimTokens(address token)` function that the recipient calls to pull their balance.
3. This isolates a blacklisted recipient: only their own claim fails; all other `finTransfer` calls succeed normally, and the nonce is consumed.

For the NEAR side, add a DAO-gated `cancel_outbound_transfer(transfer_id)` entry point that re-mints (for bridged tokens) or unlocks (for native tokens) the original amount back to the sender when a cross-chain delivery is provably undeliverable.

---

### Proof of Concept

1. Alice holds 10,000 USDC on NEAR (bridged token). She calls `ft_transfer_call` targeting the NEAR bridge contract with recipient `0xBob` on Ethereum.
2. `init_transfer_internal` burns Alice's 10,000 USDC on NEAR and emits `InitTransferEvent`. [6](#0-5) 
3. Before the relayer acts, Circle blacklists `0xBob` (e.g., sanctions enforcement).
4. The relayer calls `finTransfer` on `OmniBridge.sol` with `payload.recipient = 0xBob`.
5. `completedTransfers[nonce] = true` is written, then `IERC20(USDC).safeTransfer(0xBob, 10000e6)` reverts — USDC's `_beforeTokenTransfer` hook rejects blacklisted addresses. [7](#0-6) [8](#0-7) 
6. The EVM transaction reverts entirely; `completedTransfers[nonce]` is rolled back to `false`.
7. Every subsequent relay attempt reverts identically. The nonce is never consumed.
8. Alice's 10,000 USDC are permanently burned on NEAR. There is no `cancel_transfer` or refund path. Funds are irrecoverably frozen.

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

**File:** starknet/src/omni_bridge.cairo (L248-263)
```text
                !self.is_transfer_finalised(payload.destination_nonce), 'ERR_NONCE_ALREADY_USED',
            );
            _set_transfer_finalised(ref self, payload.destination_nonce);

            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );

            if self.is_bridge_token(payload.token_address) {
                IBridgeTokenDispatcher { contract_address: payload.token_address }
                    .mint(payload.recipient, payload.amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: payload.token_address }
                    .transfer(payload.recipient, payload.amount.into());
                assert(success, 'ERR_TRANSFER_FAILED');
            }
```
