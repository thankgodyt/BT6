### Title
Blacklisted ERC-20 Recipient Permanently Freezes Bridged Funds in `finTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`finTransfer` in `OmniBridge.sol` unconditionally pushes tokens to `payload.recipient` inside the same atomic transaction that verifies the MPC signature. If the ERC-20 transfer reverts (e.g., USDC/USDT blacklist), the whole transaction reverts, the nonce is never consumed, and no alternative delivery path exists. Because the corresponding tokens were already locked or burned on NEAR during `init_transfer`, the funds are permanently frozen with no on-chain recovery mechanism.

---

### Finding Description

`finTransfer` executes the following sequence atomically:

1. Guard: `if (completedTransfers[payload.destinationNonce]) revert NonceAlreadyUsed(...)` [1](#0-0) 
2. Mark nonce used: `completedTransfers[payload.destinationNonce] = true` [2](#0-1) 
3. Verify MPC signature via `ECDSA.recover` [3](#0-2) 
4. Transfer tokens to `payload.recipient`:
   - Native ETH: `payload.recipient.call{value: payload.amount}("")` — reverts on `!success` [4](#0-3) 
   - ERC-20 (e.g., USDC): `IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount)` [5](#0-4) 

Because step 4 is inside the same transaction as steps 1–3, any revert in the token transfer rolls back the nonce marking too. The nonce is therefore never consumed. Every subsequent attempt to call `finTransfer` with the same signed payload will also revert (the recipient remains blacklisted), making the transfer permanently undeliverable.

On the NEAR side, `init_transfer_internal` already burned or locked the tokens at the time of initiation and emitted the `InitTransferEvent`. [6](#0-5)  There is no cancel or refund path visible in the contract that would allow the NEAR-side funds to be recovered once the outbound transfer message is stored. [7](#0-6) 

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

A user who bridges USDC (or any token with a transfer blacklist, or native ETH to a contract that rejects ETH) to a recipient address that is blacklisted at delivery time will have their tokens locked/burned on NEAR with no way to receive them on EVM and no on-chain mechanism to reclaim them on NEAR. The signed MPC payload is valid but undeliverable, and the nonce can never be consumed.

---

### Likelihood Explanation

USDC and USDT both maintain on-chain blacklists and are explicitly supported tokens on the bridge. A recipient address can be blacklisted:
- After the user initiates the transfer but before the relayer finalizes it (race condition).
- Deliberately, by a user who knows their address will be blacklisted (e.g., under regulatory action) and initiates a transfer to grief the protocol or themselves.
- By a contract recipient that rejects ETH or ERC-20 callbacks.

The scenario requires no privileged access and is reachable by any bridge user.

---

### Recommendation

Separate the token delivery from the nonce finalization, or add a pull-based fallback:

1. **Two-step delivery**: Mark the nonce as used and credit the amount to an internal claimable balance for `payload.recipient`. Add a separate `claimTransfer(nonce)` function that the recipient (or anyone on their behalf) calls to pull the tokens. This way the nonce is consumed regardless of whether the immediate push succeeds.

2. **Try-catch delivery with escrow**: Use a low-level call with a success check; on failure, escrow the tokens in the bridge contract under the recipient's address and emit an event, allowing an admin or the recipient to redirect the escrowed funds later.

3. **Pre-flight blacklist check**: Not sufficient alone (blacklisting can happen between check and execution), but can be combined with option 1 or 2.

---

### Proof of Concept

1. Alice holds 10,000 USDC on Ethereum and bridges them to NEAR via `init_transfer`. Tokens are locked in the EVM bridge.
2. NEAR-side `fin_transfer` is called by a relayer; NEAR mints/unlocks tokens for Alice on NEAR. Alice now holds NEAR-side USDC.
3. Alice calls `ft_transfer_call` on NEAR to bridge 10,000 USDC back to her Ethereum address `0xAlice`. Tokens are burned on NEAR; `InitTransferEvent` is emitted; the transfer message is stored. [6](#0-5) 
4. Between step 3 and step 5, Circle blacklists `0xAlice` on the USDC contract.
5. The relayer calls `finTransfer` on `OmniBridge.sol` with the valid MPC-signed payload targeting `0xAlice`. [8](#0-7) 
6. `IERC20(usdc).safeTransfer(0xAlice, 10000e6)` reverts because `0xAlice` is blacklisted. [5](#0-4) 
7. The entire transaction reverts; `completedTransfers[nonce]` is never set to `true`.
8. Every future call to `finTransfer` with the same payload reverts identically.
9. Alice's 10,000 USDC are permanently burned on NEAR and undeliverable on Ethereum — funds are frozen with no recovery path.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-282)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-285)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L287-287)
```text
        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L311-313)
```text
        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L319-322)
```text
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L351-354)
```text
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
```

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

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
    }
```
