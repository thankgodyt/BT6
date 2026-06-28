### Title
Blacklisted EVM Recipient Permanently Freezes Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

When a user bridges tokens from NEAR to an EVM chain, the MPC signature cryptographically binds the destination `recipient` address. If that EVM address is subsequently blacklisted by the destination token (e.g., USDC, USDT), every call to `finTransfer` will revert. Because the nonce reverts with the transaction, it is never consumed — but the transfer can never succeed either, since the recipient is immutably fixed in the signed payload. There is no mechanism in the bridge to re-sign with a different recipient or to cancel the transfer and recover the tokens locked on NEAR. The result is permanent freezing of the user's bridged funds.

---

### Finding Description

**Step 1 — Tokens are locked on NEAR.**

When a user calls `ft_transfer_call` on a NEAR token contract, the bridge's `ft_on_transfer` entry point is invoked, which calls `init_transfer`. The tokens are locked or burned on NEAR and a `TransferMessage` is stored in `pending_transfers`. [1](#0-0) 

**Step 2 — MPC signature binds the recipient.**

A trusted relayer calls `sign_transfer`, which constructs a `TransferMessagePayload` embedding `transfer_message.recipient` (the user's EVM address) and requests an MPC signature over it. The recipient is part of the signed hash and cannot be altered without a new signature. [2](#0-1) 

**Step 3 — `finTransfer` on EVM marks the nonce used before the token transfer.**

In `OmniBridge.sol`, `finTransfer` sets `completedTransfers[payload.destinationNonce] = true` at line 287, then verifies the MPC signature, then attempts to transfer tokens to `payload.recipient`. [3](#0-2) 

**Step 4 — Blacklisted recipient causes permanent revert.**

For native (non-bridge) ERC-20 tokens such as USDC or USDT, the transfer path is:

```solidity
IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount);
```

`SafeERC20.safeTransfer` wraps the call and reverts if the underlying `transfer` returns `false` or reverts. If `payload.recipient` is blacklisted in the token, the call reverts. Because Solidity reverts roll back all state changes in the transaction, `completedTransfers[payload.destinationNonce]` is also rolled back to `false`. The nonce is not consumed. [4](#0-3) 

**Step 5 — No recovery path exists.**

The nonce is not consumed, so the transfer is not "used up." However, the recipient is cryptographically fixed in the MPC signature. There is no function in the bridge to:
- Re-sign the transfer with a different recipient address.
- Cancel the pending transfer and refund the locked/burned NEAR-side tokens.
- Allow the user to specify an alternative recipient for delivery.

The `update_transfer_fee` function only allows updating the fee, not the recipient. [5](#0-4) 

The same structural issue exists in the Starknet gateway, where `_set_transfer_finalised` is called before the token transfer and the assert on transfer success causes a full revert if the recipient is blocked: [6](#0-5) 

---

### Impact Explanation

Tokens locked or burned on NEAR during `init_transfer` are permanently unrecoverable if the designated EVM recipient becomes blacklisted in the destination token after the transfer is initiated. The NEAR-side tokens remain locked in the bridge contract with no refund path. This constitutes **permanent freezing of bridged funds**, matching the critical impact class.

---

### Likelihood Explanation

USDC and USDT — two of the most commonly bridged assets — maintain on-chain blacklists. A user whose EVM address is blacklisted by Circle or Tether (e.g., due to regulatory action, sanctions, or exchange enforcement) after initiating a NEAR → EVM bridge transfer will have their funds permanently frozen. This is a realistic scenario given the regulatory environment and the bridge's support for these tokens. The user has no control over when blacklisting occurs relative to their bridge transaction.

---

### Recommendation

1. **Allow recipient override on retry**: Permit the original sender (verified via the stored `TransferMessage.sender`) to request a new MPC signature with a different recipient address, invalidating the old signature by consuming the nonce or updating the stored transfer.

2. **Add a cancel/refund path**: Introduce a `cancel_transfer` function on the NEAR side that, after a timeout or upon explicit user request, burns the destination-nonce entry and refunds the locked/burned tokens to the original sender on NEAR.

3. **Alternatively, use a pull pattern on EVM**: Instead of pushing tokens directly to `payload.recipient` in `finTransfer`, credit the amount to a claimable balance mapping keyed by `(nonce, recipient)`. The recipient (or a delegate) can then pull the tokens separately, isolating transfer failures from nonce consumption.

---

### Proof of Concept

1. Alice holds 10,000 USDC on NEAR and calls `ft_transfer_call` to bridge to her EVM address `0xAlice`. Tokens are locked on NEAR; `TransferMessage` is stored.
2. A relayer calls `sign_transfer`; the MPC network signs a payload containing `recipient = 0xAlice`.
3. Before the relayer submits `finTransfer` on EVM, Circle blacklists `0xAlice` (e.g., due to a regulatory freeze).
4. The relayer calls `OmniBridge.finTransfer(signature, payload)`. Execution reaches `IERC20(usdc).safeTransfer(0xAlice, amount)`, which reverts with `"Blacklisted"`.
5. The entire transaction reverts. `completedTransfers[nonce]` remains `false`.
6. Every subsequent attempt to call `finTransfer` with the same signed payload reverts identically.
7. No function exists to re-sign with a different recipient or to cancel the transfer and recover the NEAR-side tokens.
8. Alice's 10,000 USDC equivalent is permanently frozen in the NEAR bridge contract.

### Citations

**File:** near/omni-bridge/src/lib.rs (L253-263)
```rust
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
```

**File:** near/omni-bridge/src/lib.rs (L386-436)
```rust
    #[payable]
    #[pause]
    pub fn update_transfer_fee(&mut self, transfer_id: TransferId, fee: UpdateFee) {
        match fee {
            UpdateFee::Fee(fee) => {
                let mut transfer = self.get_transfer_message_storage(transfer_id);

                require!(
                    transfer.message.origin_transfer_id.is_none(),
                    BridgeError::UpdateFeeNotAllowedForTransfer.as_ref()
                );

                let current_fee = transfer.message.fee;
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );

                require!(
                    fee.fee == current_fee.fee
                        || OmniAddress::Near(env::predecessor_account_id())
                            == transfer.message.sender,
                    BridgeError::SenderCanUpdateTokenFeeOnly.as_ref()
                );

                let diff_native_fee = fee
                    .native_fee
                    .0
                    .checked_sub(current_fee.native_fee.0)
                    .near_expect(BridgeError::LowerFee);

                require!(
                    NearToken::from_yoctonear(diff_native_fee) == env::attached_deposit(),
                    BridgeError::InvalidAttachedDeposit.as_ref()
                );

                transfer.message.fee = fee;
                self.insert_raw_transfer(transfer.message.clone(), transfer.owner);

                env::log_str(
                    &OmniBridgeEvent::UpdateFeeEvent {
                        transfer_message: transfer.message,
                    }
                    .to_log_string(),
                );
            }
            UpdateFee::Proof(_) => {
                env::panic_str(BridgeError::UnsupportedFeeUpdateProof.to_string().as_str())
            }
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L491-520)
```rust
        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };

        let payload = near_sdk::env::keccak256_array(
            transfer_payload
                .encode_hashable()
                .near_expect(BridgeError::Borsh),
        );

        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_TRANSFER_CALLBACK_GAS)
                    .sign_transfer_callback(transfer_payload, &transfer_message.fee),
            )
```

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

**File:** starknet/src/omni_bridge.cairo (L247-263)
```text
            assert(
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
