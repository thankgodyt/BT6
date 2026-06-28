### Title
Malicious EVM Recipient Contract Can Permanently Freeze Bridged Native ETH Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
In `OmniBridge.finTransfer()`, when bridging native ETH (`tokenAddress == address(0)`), the function hard-reverts if the recipient contract rejects the ETH call. Because the NEAR side has already locked the sender's tokens and there is no cancellation or refund path for a pending transfer, a malicious or broken EVM recipient contract can permanently freeze the sender's bridged funds.

### Finding Description
`OmniBridge.finTransfer()` handles native ETH delivery as follows:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287

// ... signature verification ...

if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();           // line 322
}
``` [1](#0-0) 

If `payload.recipient` is a contract whose `receive()` / `fallback()` reverts, the entire transaction reverts (including the `completedTransfers` write), so the destination nonce is never consumed. The MPC-signed payload is still valid and the relayer can retry, but every retry will revert for the same reason.

On the NEAR side, the sender's tokens were already locked (or burned for deployed tokens) inside `init_transfer_internal` when the transfer was initiated: [2](#0-1) 

The locked tokens are stored in `pending_transfers` and are only released when `claim_fee_callback` successfully removes the transfer message after a verified EVM `FinTransfer` proof: [3](#0-2) 

There is no `cancel_transfer`, timeout, or refund path for a pending NEAR-originating transfer. Without a successful `finTransfer` on EVM, no valid proof can be generated, so `claim_fee` on NEAR can never be called, and the locked tokens are permanently irrecoverable.

### Impact Explanation
A user who bridges native ETH to an EVM contract address that rejects ETH (maliciously or due to a contract upgrade/compromise) will have their NEAR-side tokens permanently frozen. The MPC signature is bound to the original recipient; neither the relayer nor the sender can redirect the transfer to a different address. The sender loses the full bridged amount with no recovery mechanism.

**Impact: Critical** — permanent freezing of bridged funds.

### Likelihood Explanation
The recipient address is chosen by the sender at initiation time. The scenario requires the EVM recipient to be a contract that rejects ETH — either because the sender made an error, the contract was upgraded after the transfer was initiated, or a third party deliberately set up a blocking contract as the recipient. This is an uncommon but realistic scenario (e.g., multisig wallets, proxy contracts, or contracts with strict `receive()` guards).

**Likelihood: Low**

### Recommendation
Two complementary mitigations:

1. **Wrap-and-pull pattern**: Instead of pushing ETH directly to the recipient, credit the amount to a claimable balance mapping and let the recipient pull it. This eliminates the revert-on-receive vector entirely.

2. **Cancellation / timeout mechanism on NEAR**: Add a `cancel_transfer` function (callable by the original sender after a timeout) that removes the entry from `pending_transfers` and refunds the locked/burned tokens. This provides a recovery path regardless of EVM-side failures.

### Proof of Concept
1. Alice initiates a NEAR → EVM native ETH bridge transfer, specifying `recipient = address(MaliciousContract)` where `MaliciousContract.receive()` always reverts.
2. The MPC signs the `TransferMessagePayload` binding `recipient` to `MaliciousContract`.
3. The relayer calls `OmniBridge.finTransfer(signature, payload)`.
4. Execution reaches line 319: `(bool success,) = payload.recipient.call{value: payload.amount}("")` — `MaliciousContract` reverts, `success = false`.
5. Line 322 fires: `revert FailedToSendEther()` — the entire transaction reverts, including the `completedTransfers` write.
6. The relayer retries indefinitely; every attempt reverts identically.
7. On NEAR, Alice's tokens remain in `pending_transfers` with no cancellation path. The funds are permanently frozen. [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-322)
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
```

**File:** near/omni-bridge/src/lib.rs (L1057-1064)
```rust
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(CLAIM_FEE_CALLBACK_GAS)
                .claim_fee_callback(&env::predecessor_account_id()),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1094-1134)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);

        if let Some(origin_transfer_id) = transfer_message.origin_transfer_id.clone() {
            let mut fast_transfer = FastTransfer::from_transfer(
                transfer_message.clone(),
                self.get_token_id(&transfer_message.token),
            );
            fast_transfer.transfer_id = origin_transfer_id;

            if let Some(fast_transfer_status) = self.get_fast_transfer_status(&fast_transfer.id()) {
                // For fast transfers we need to wait for finalization of the first leg (Origin chain -> Near) before allowing fee claim.
                // This confirms that fast transfer was executed with correct parameters.
                // Othewise malicious relayer can create a fast transfer with arbitrary high fee and claim it here.
                if fast_transfer_status.finalised {
                    self.remove_fast_transfer(&fast_transfer.id());
                } else {
                    env::panic_str(BridgeError::FastTransferNotFinalised.to_string().as_str());
                }
            }
        }

        let token = self.get_token_id(&transfer_message.token);
        let token_address = self
            .get_token_address(transfer_message.get_destination_chain(), token.clone())
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let denormalized_amount = Self::denormalize_amount(
            fin_transfer.amount.0,
            self.token_decimals
                .get(&token_address)
                .near_expect(BridgeError::TokenDecimalsNotFound),
        );
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
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
