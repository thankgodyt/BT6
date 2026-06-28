### Title
Permanent Freezing of Bridged Funds When EVM Recipient Is Token-Blacklisted — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.sol::finTransfer` unconditionally pushes tokens to `payload.recipient` using `safeTransfer`. If the recipient address is blacklisted by a token with transfer restrictions (e.g., USDC), every finalization attempt reverts. Because the MPC signature commits to the exact recipient and no cancel/redirect mechanism exists on the NEAR side, the tokens locked or burned on NEAR are permanently unrecoverable.

### Finding Description

In `finTransfer`, the nonce is marked used before the token transfer (CEI pattern for reentrancy safety), and then tokens are pushed directly to `payload.recipient`:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287
// ...
IERC20(payload.tokenAddress).safeTransfer(             // line 351-354
    payload.recipient,
    payload.amount
);
``` [1](#0-0) 

If `payload.recipient` is on the USDC (or any token with a blacklist) blocklist, `safeTransfer` reverts, rolling back the entire transaction including the nonce mark. The relayer can retry indefinitely, but every attempt will revert for the same reason.

On the NEAR side, when a user initiates an outbound transfer, tokens are either burned (for deployed/bridged tokens) or locked (for native tokens) and a `TransferMessage` is stored in `pending_transfers`: [2](#0-1) 

The MPC then signs a `TransferMessagePayload` that encodes the recipient address. There is no public function to cancel a pending outbound transfer or redirect it to a different recipient — `remove_transfer_message` is internal and only reachable through finalization callbacks: [3](#0-2) 

The only path that removes a `pending_transfer` entry is `claim_fee_callback`, which requires a proof that the EVM side already finalized the transfer — a proof that can never be produced if `finTransfer` always reverts: [4](#0-3) 

### Impact Explanation

A user who initiates a NEAR → EVM transfer of USDC (or any token with a blacklist) to an EVM address that is (or becomes) blacklisted will have their tokens permanently frozen:

- **Burned tokens** (deployed/bridged tokens): burned on NEAR, never minted on EVM — permanently destroyed.
- **Locked tokens** (native tokens): locked in the NEAR bridge contract forever, with no release path.

This matches the allowed impact: *permanent freezing of bridged funds across NEAR and EVM flows*.

### Likelihood Explanation

Low. USDC blacklisting is a real-world event (OFAC sanctions, exchange enforcement). A user whose EVM address is sanctioned after initiating a bridge transfer, or who unknowingly bridges to a sanctioned address, triggers this condition. No attacker action is required beyond the normal bridge flow.

### Recommendation

Adopt a pull-over-push pattern for EVM token delivery. Instead of pushing tokens to `payload.recipient` inside `finTransfer`, record the claimable balance in a mapping and let the recipient (or any address they designate) call a separate `claimTransfer(nonce)` function. This decouples finalization (nonce consumption, accounting) from delivery, so a blacklisted recipient does not block the protocol and the user retains the ability to redirect funds via an alternative address.

### Proof of Concept

1. Alice holds USDC on NEAR and calls `ft_transfer_call` to bridge 1000 USDC to her EVM address `0xAlice`. NEAR burns the tokens and stores the `TransferMessage` in `pending_transfers`.
2. Alice calls `sign_transfer`; the MPC signs a `TransferMessagePayload` with `recipient = 0xAlice`.
3. Before the relayer submits the signature, `0xAlice` is added to the USDC blacklist on Ethereum.
4. The relayer calls `OmniBridge.finTransfer(sig, payload)`. Execution reaches line 351: `IERC20(USDC).safeTransfer(0xAlice, 1000e6)`. USDC reverts because `0xAlice` is blacklisted. The entire transaction reverts.
5. Every subsequent `finTransfer` attempt reverts identically.
6. The NEAR `pending_transfers` entry for Alice's transfer can never be removed (no proof of EVM finalization exists). Alice's 1000 USDC are permanently lost. [5](#0-4) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-355)
```text
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
```

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
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
