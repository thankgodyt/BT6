Audit Report

## Title
Blacklisted EVM Recipient Causes Permanent Freezing of Funds Locked in NEAR Bridge Contract — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `near/omni-bridge/src/lib.rs`)

## Summary
When a user initiates a NEAR→EVM transfer of a blacklist-capable token (e.g., USDC), and the EVM recipient is subsequently blacklisted by the token operator, `finTransfer` on the EVM bridge will always revert because `safeTransfer` to a blacklisted address reverts. Because the MPC signature is cryptographically bound to the specific recipient and the NEAR bridge has no cancel/refund path for pending outbound transfers, the locked tokens are permanently frozen in the NEAR bridge contract.

## Finding Description
**Root cause — EVM side:** In `OmniBridge.finTransfer`, `completedTransfers[payload.destinationNonce] = true` is written at line 287 before the token transfer at line 351. If `IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount)` reverts (e.g., USDC blacklist check), the entire EVM transaction reverts, rolling back the nonce write. The nonce is therefore never consumed, and every subsequent retry by the relayer will revert identically. [1](#0-0) [2](#0-1) 

**Root cause — NEAR side:** `sign_transfer` constructs a `TransferMessagePayload` that commits to `recipient: transfer_message.recipient` and requests the MPC network to sign the keccak256 hash of this payload. No alternative recipient can be substituted without a new MPC signing round, which the protocol does not support for an already-initiated transfer. [3](#0-2) 

**Root cause — no cancel path:** In `sign_transfer_callback`, the transfer message is removed from `pending_transfers` only when `fee.is_zero()`. When a fee is present, the message remains until `claim_fee` is called, which itself requires proof of successful EVM finalization — a proof that can never be produced if `finTransfer` always reverts. There is no public cancel or timeout-based refund function that allows the original sender to recover locked tokens. [4](#0-3) [5](#0-4) 

**Exploit path:**
1. User calls `ft_transfer_call` on USDC.e → `init_transfer` on NEAR bridge → tokens locked, transfer stored in `pending_transfers`.
2. Relayer calls `sign_transfer` → MPC signs payload committing to `recipient = 0xAlice`.
3. USDC operator blacklists `0xAlice` (regulatory action, sanction, etc.).
4. Relayer submits `finTransfer(sig, payload)` on EVM → `safeTransfer(0xAlice, amount)` reverts → entire transaction reverts → nonce not consumed.
5. Every retry reverts identically. No re-signing to a different recipient is possible.
6. On NEAR, the transfer message stays in `pending_transfers` indefinitely; no cancel function exists to return the locked tokens.

## Impact Explanation
Permanent freezing of bridged funds: the user's USDC locked in the NEAR bridge contract is irrecoverable. This matches the Critical impact class — "permanent freezing of bridged funds across NEAR, EVM flows" — because neither the user nor any protocol participant can retrieve the locked tokens through any on-chain mechanism. [6](#0-5) [7](#0-6) 

## Likelihood Explanation
USDC blacklisting is a real, exercised feature (regulatory sanctions, court orders). The exposure window is the time between `init_transfer` on NEAR and `finTransfer` on EVM; for light-client-verified chains this can span hours. A user whose address is blacklisted during this window — or who unknowingly initiates a transfer to an already-blacklisted address — will have funds permanently frozen. Likelihood is Low-Medium: rare but entirely within normal USDC operating parameters and requires no attacker capability beyond the USDC operator exercising its documented authority.

## Recommendation
1. **NEAR side — add a cancel/timeout refund function:** Allow the original sender (or DAO after a timeout) to call a `cancel_transfer` function that removes the entry from `pending_transfers` and returns the locked tokens via `ft_transfer`, callable after a configurable timeout or upon submission of repeated EVM-side failure proofs.
2. **EVM side — consume the nonce on failure:** Wrap the `safeTransfer` in a try/catch; on failure, store the funds in a per-recipient claimable escrow so the nonce is consumed and the NEAR side can be notified of completion (even if delivery is deferred). This prevents indefinite retry loops.
3. **Alternative:** Allow the MPC to re-sign a transfer with a different recipient upon explicit, authorized user request with proof of blacklisting.

## Proof of Concept
**Local integration test plan:**

1. Deploy a mock ERC20 with a blacklist (mirroring USDC's `_blacklisted` mapping and `transfer` revert).
2. Deploy `OmniBridge` on a local EVM fork; register the mock token as a native (non-bridge) token.
3. Simulate `init_transfer` on NEAR (store a `TransferMessage` in `pending_transfers` with `recipient = 0xAlice`).
4. Construct a valid `TransferMessagePayload` with `recipient = 0xAlice`; sign it with the test MPC key.
5. Blacklist `0xAlice` on the mock ERC20.
6. Call `OmniBridge.finTransfer(sig, payload)` — assert it reverts.
7. Assert `completedTransfers[destinationNonce]` is `false` (nonce not consumed).
8. Retry `finTransfer` — assert it reverts again.
9. On the NEAR side, assert no public function exists to remove the `pending_transfers` entry and return tokens to the sender.
10. Assert the mock token balance of `OmniBridge` (NEAR side) is unchanged — funds permanently locked. [8](#0-7) [9](#0-8)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L655-668)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```
