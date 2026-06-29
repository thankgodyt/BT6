### Title
Permanent Loss of Bridged Funds When EVM Recipient Is Blacklisted After NEAR-Side Burn With No Recovery Mechanism - (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `near/omni-bridge/src/lib.rs`)

### Summary

When a user initiates a NEAR → EVM transfer, tokens are irreversibly burned on NEAR and a MPC-signed `TransferMessagePayload` is produced with a fixed `recipient` address. If that EVM address is subsequently blacklisted by a token issuer (e.g., Circle for USDC), every attempt to call `finTransfer` on the EVM bridge will revert. Because neither the stored `TransferMessage` on NEAR nor the MPC-signed payload exposes any mechanism to update the `recipient`, the burned tokens are permanently unrecoverable.

### Finding Description

**NEAR-side burn is irreversible.** In `near/omni-bridge/src/lib.rs`, `init_transfer_internal` burns the user's tokens immediately: [1](#0-0) 

**Recipient is baked into the MPC-signed payload.** `sign_transfer` reads `transfer_message.recipient` from the stored `TransferMessage` and commits it into the signed `TransferMessagePayload` sent to the MPC network: [2](#0-1) 

**No function exists to update the recipient.** The only mutable operation on a pending transfer is `update_transfer_fee`, which is strictly limited to the `fee` field and explicitly rejects any other modification: [3](#0-2) 

**EVM `finTransfer` will permanently revert for a blacklisted recipient.** For native ERC-20 tokens (e.g., USDC held in the bridge vault), the transfer path is: [4](#0-3) 

`SafeERC20.safeTransfer` will revert if `payload.recipient` is on Circle's blacklist. Because the MPC signature cryptographically binds the `recipient` field, no alternative recipient can be substituted without producing a new signature — which is impossible without changing the stored `TransferMessage` on NEAR.

**Nonce replay is not the escape hatch.** The destination nonce is marked used only if the transaction succeeds; a revert leaves it unmarked. However, every retry with the same signed payload hits the same blacklisted recipient and reverts again, making the transfer permanently unexecutable.

### Impact Explanation

Tokens burned on NEAR are gone. The EVM bridge vault retains the corresponding USDC, but it can never be released to the intended recipient (blacklisted) and there is no governance or user-callable path to redirect the funds. This constitutes a **permanent, material loss of bridged funds** for the affected user.

### Likelihood Explanation

The attack mirrors the scenario described in the reference report: an adversary monitors pending NEAR → EVM transfers, dusts the target EVM address with OFAC-sanctioned or exploit-tainted tokens, and waits for Circle to blacklist that address. The bridge's lack of any recipient-update or fund-recovery function means a single successful blacklisting event permanently freezes the in-flight funds. The attack is realistic wherever USDC (or any token with an issuer-controlled blacklist) is bridged via the Omni Bridge.

### Recommendation

1. **Add an `update_recipient` function** on the NEAR bridge (restricted to the original sender) that allows changing `TransferMessage.recipient` before `sign_transfer` is called, analogous to how `update_transfer_fee` works for fees.
2. **Add a DAO-gated recovery action** that can redirect funds from a transfer whose `finTransfer` has never been successfully executed on the destination chain, to a safe address specified by governance.
3. Consider emitting a `FailedFinTransfer`-style event on the EVM side so off-chain monitoring can detect permanently stuck transfers.

### Proof of Concept

1. Alice calls `ft_transfer_call` on NEAR with `msg = InitTransfer { recipient: "0xAlice", ... }`. Her NEAR-side USDC is burned; the `TransferMessage` is stored with `recipient = OmniAddress::Eth(0xAlice)`. [5](#0-4) 
2. A relayer calls `sign_transfer`. The MPC produces a signature over a payload that includes `recipient = 0xAlice`. [6](#0-5) 
3. While the signed payload is in-flight, an attacker sends OFAC-sanctioned USDC to `0xAlice` on Ethereum. Circle blacklists `0xAlice`.
4. The relayer calls `finTransfer` on `OmniBridge.sol`. Signature verification passes, but `IERC20(USDC).safeTransfer(0xAlice, amount)` reverts because `0xAlice` is blacklisted. [4](#0-3) 
5. Every subsequent retry reverts identically. Alice's NEAR-side USDC is permanently burned with no path to recovery, because `update_transfer_fee` is the only mutation allowed on the stored transfer and it cannot change the recipient. [3](#0-2)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L491-519)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-355)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```
