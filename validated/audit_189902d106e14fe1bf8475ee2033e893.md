### Title
Detached `burn_tokens_if_needed` Promise Silently Ignores Burn Failures, Enabling Token Supply Inflation — (`near/omni-bridge/src/lib.rs`)

### Summary

`burn_tokens_if_needed` fires a cross-contract `burn` call with `.detach()`, meaning any failure of the burn is silently ignored. Because the `InitTransferEvent` is emitted in the same transaction — before the burn receipt executes — a burn failure leaves the NEAR-side tokens un-destroyed while the relayer still processes the event and unlocks/mints tokens on the destination chain, inflating the total supply.

### Finding Description

`burn_tokens_if_needed` is a helper used in every critical outbound-transfer path for deployed (bridged) tokens:

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)
            .burn(amount)
            .detach();   // ← result never checked
    }
}
``` [1](#0-0) 

In NEAR, `.detach()` schedules the cross-contract call as a fire-and-forget receipt. The calling function commits its own state changes — including emitting the `InitTransferEvent` log — before the burn receipt even executes. If the burn receipt fails (out-of-gas, token contract panic, storage exhaustion, or any future restriction added to the token contract), the failure is invisible to the bridge.

The most critical call site is `init_transfer_internal`, which is reached when a user bridges a deployed token (e.g., wETH on NEAR) back to its origin chain:

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);  // detached
    self.lock_tokens_if_needed(...);
}
env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
U128(0)
``` [2](#0-1) 

The `InitTransferEvent` is committed in the same receipt as the `burn_tokens_if_needed` call. The burn executes in a subsequent receipt. If that receipt fails, the event is already on-chain and the relayer will process it.

The same pattern appears in the rollback path of `fin_transfer_send_tokens_callback` (line 1703), `resolve_fast_transfer` (line 904), and `fast_fin_transfer_to_other_chain` (line 932). [3](#0-2) [4](#0-3) [5](#0-4) 

The project's own security checklist in `near/CLAUDE.md` explicitly flags this pattern:

> **Check .detach() usage**: Detached promises should only be used for non-critical operations [6](#0-5) 

### Impact Explanation

If the burn receipt fails silently:

1. The `InitTransferEvent` is already committed on NEAR.
2. The relayer reads the event and unlocks/mints the equivalent tokens on the destination chain (e.g., ETH unlocked on Ethereum).
3. The NEAR-side deployed tokens are **not** destroyed — they remain in the bridge contract.
4. Total supply of the bridged asset is inflated: tokens exist both on the destination chain (unlocked) and on NEAR (un-burned in the bridge).

This is a direct, permanent loss of protocol solvency — the bridge's locked collateral on the origin chain no longer backs the circulating supply.

### Likelihood Explanation

The burn can fail if:
- `BURN_TOKEN_GAS` is set too low for the token contract's execution (gas exhaustion in the burn receipt).
- The `omni-token` contract is upgraded to add a pause or restriction on `burn`.
- The bridge's storage account on the token contract is exhausted.

The `omni-token` contract is upgradeable (it uses UUPS), so future changes to the burn path are a realistic concern. Gas exhaustion is also realistic if the token contract's `internal_withdraw` path becomes more expensive after an upgrade. The user does not need to do anything special — they simply initiate a normal bridge transfer of a deployed token.

### Recommendation

Replace `.detach()` with a chained callback that checks the burn result and reverts the `InitTransferEvent` emission (or panics) if the burn failed. The pattern already used in `process_fin_transfer_to_near` — where `send_tokens` is chained to `fin_transfer_send_tokens_callback` — is the correct model:

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) -> Option<Promise> {
    if self.is_deployed_token(&token) {
        Some(
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
        )
    } else {
        None
    }
}
```

The caller must chain a callback that panics on failure, ensuring the parent receipt also reverts and the `InitTransferEvent` is never committed if the burn fails.

### Proof of Concept

1. User holds 1000 wETH (a deployed token on NEAR, origin: Ethereum).
2. User calls `ft_transfer_call` on the wETH token contract, sending 1000 wETH to the bridge with an `InitTransfer` message targeting an Ethereum address.
3. Bridge's `ft_on_transfer` → `init_transfer_internal` fires `burn_tokens_if_needed(...).detach()` and immediately emits `InitTransferEvent`.
4. The burn receipt fails (e.g., `BURN_TOKEN_GAS` exhausted due to a recent token contract upgrade).
5. The failure is silent — the bridge's state shows the transfer as pending, the event is on-chain.
6. The relayer reads `InitTransferEvent` and calls `finTransfer` on the EVM `OmniBridge`, unlocking 1000 ETH to the user's Ethereum address.
7. The 1000 wETH remain in the bridge contract on NEAR, un-burned.
8. Total wETH supply is now 1000 units higher than the ETH locked on Ethereum — the bridge is insolvent by 1000 ETH. [1](#0-0) [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L903-905)
```rust
        // Burn the tokens to ensure the locked tokens are not double-minted
        self.burn_tokens_if_needed(token_id.clone(), amount);

```

**File:** near/omni-bridge/src/lib.rs (L931-933)
```rust

        self.burn_tokens_if_needed(fast_transfer.token_id.clone(), amount_without_fee.into());

```

**File:** near/omni-bridge/src/lib.rs (L1702-1710)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );
```

**File:** near/omni-bridge/src/lib.rs (L1806-1813)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
    }
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

**File:** near/CLAUDE.md (L228-228)
```markdown
4. **Check .detach() usage**: Detached promises should only be used for non-critical operations
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-367)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }

        finTransferExtension(payload);

        emit BridgeTypes.FinTransfer(
            payload.originChain,
            payload.originNonce,
            payload.tokenAddress,
            payload.amount,
            payload.recipient,
            payload.feeRecipient
        );
    }
```
