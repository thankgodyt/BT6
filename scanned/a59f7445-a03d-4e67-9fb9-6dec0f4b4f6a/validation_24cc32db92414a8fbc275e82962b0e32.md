### Title
Blacklisted EVM Recipient Causes Permanent Freezing of Funds Locked in NEAR Bridge Contract — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates a NEAR→EVM transfer of a blacklist-capable token (e.g., USDC), and the EVM recipient address is subsequently blacklisted by the token operator, the `finTransfer` call on the EVM bridge will always revert. Because the MPC signature is cryptographically bound to the specific recipient address and there is no cancel/refund path on the NEAR side, the locked funds are permanently frozen in the NEAR bridge contract.

---

### Finding Description

**NEAR → EVM outbound flow:**

1. A user calls `ft_transfer_call` on a NEAR token (e.g., USDC.e), which triggers `init_transfer` on the NEAR bridge. The transfer message — including the EVM recipient address — is stored in `pending_transfers`. [1](#0-0) 

2. A trusted relayer calls `sign_transfer`, which requests the MPC network to sign a `TransferMessagePayload` that commits to the exact `recipient` address. [2](#0-1) 

3. The relayer submits the signed payload to `finTransfer` on the EVM bridge. For native (non-bridge) tokens such as USDC, the contract executes:

```solidity
IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount);
``` [3](#0-2) 

4. If `payload.recipient` has been blacklisted by the USDC operator between step 1 and step 3, `safeTransfer` reverts. Because Solidity reverts roll back all state changes, the `completedTransfers[payload.destinationNonce] = true` write at line 287 is also rolled back. [4](#0-3) 

5. The nonce is not consumed, so the relayer can retry — but every retry will revert for the same reason. The MPC signature is bound to the blacklisted recipient; no alternative recipient can be substituted without a new MPC signing round, which the protocol does not support for an already-initiated transfer.

6. On the NEAR side, the transfer message remains in `pending_transfers` indefinitely. There is no public `cancel_transfer` or admin rescue function that removes the entry and refunds the user's tokens. [5](#0-4) 

The same pattern applies to the Starknet bridge, where `_set_transfer_finalised` is called before the token transfer and the whole transaction reverts on failure, leaving the NEAR-side funds locked with no recovery path. [6](#0-5) 

---

### Impact Explanation

Bridged funds (e.g., USDC locked in the NEAR bridge contract) are permanently frozen. The user cannot receive their tokens on the destination chain, and there is no on-chain mechanism to cancel the transfer and recover the original deposit. This matches the **Critical** impact class: permanent freezing of bridged funds.

---

### Likelihood Explanation

USDC blacklisting is a real, documented occurrence (e.g., sanctioned addresses, regulatory actions). The window of exposure is the time between `init_transfer` on NEAR and `finTransfer` on EVM. For light-client-verified chains (Ethereum), this window can span hours. A user whose address is blacklisted during this window — or who unknowingly initiates a transfer to an already-blacklisted address — will have their funds permanently frozen. Likelihood is **Low-Medium**: rare but realistic and entirely within the normal operating parameters of USDC.

---

### Recommendation

1. **Add a cancel/refund function on the NEAR side** that allows the original sender (or DAO) to remove a pending transfer from `pending_transfers` and return the locked tokens to the sender, callable after a timeout or upon proof of repeated EVM-side failure.
2. **On the EVM side**, consider wrapping the `safeTransfer` in a try/catch and, on failure, storing the funds in a claimable escrow keyed by recipient, so the nonce can be consumed and the NEAR side can be notified of completion (even if delivery is deferred).
3. Alternatively, allow the MPC to re-sign a transfer with a different recipient upon explicit user request and proof of blacklisting, with appropriate authorization checks.

---

### Proof of Concept

1. Alice holds USDC on NEAR and calls `ft_transfer_call` to bridge 10,000 USDC to her Ethereum address `0xAlice`. The NEAR bridge stores the transfer in `pending_transfers` and locks the tokens.
2. Before the relayer finalizes the transfer, USDC's operator blacklists `0xAlice` (e.g., due to a regulatory order).
3. The relayer calls `OmniBridge.finTransfer(signature, payload)` where `payload.recipient = 0xAlice` and `payload.tokenAddress = USDC`.
4. `IERC20(USDC).safeTransfer(0xAlice, 10000e6)` reverts because `0xAlice` is blacklisted.
5. The entire transaction reverts. The relayer retries — same result, indefinitely.
6. Alice's 10,000 USDC remain locked in the NEAR bridge contract forever. No cancel function exists to recover them. [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L447-521)
```rust
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );

        let message = DestinationChainMsg::from_json(&transfer_message.msg)
            .and_then(|s| s.destination_msg())
            .unwrap_or_default();

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
    }
```

**File:** near/omni-bridge/src/lib.rs (L523-557)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-355)
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
