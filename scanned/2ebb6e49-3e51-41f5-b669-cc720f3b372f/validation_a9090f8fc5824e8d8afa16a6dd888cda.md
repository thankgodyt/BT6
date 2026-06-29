### Title
`finTransfer` Permanently Blocked by Token-Blacklisted Recipient, Freezing Bridged Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol::finTransfer` uses a push-transfer pattern to deliver tokens directly to `payload.recipient`. If the recipient address is blacklisted by a token with transfer restrictions (e.g., USDC, USDT), the `safeTransfer` call reverts, the entire transaction reverts, and no alternative delivery or recovery path exists. The user's funds, already burned or locked on NEAR, are permanently frozen.

---

### Finding Description

`finTransfer` is the EVM-side finalisation function. It verifies an MPC signature from the NEAR bridge, marks the destination nonce as consumed, and then pushes tokens to the recipient:

```solidity
// OmniBridge.sol line 287
completedTransfers[payload.destinationNonce] = true;

// ... signature verification ...

// OmniBridge.sol lines 351-354
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount
);
```

Because `completedTransfers[payload.destinationNonce] = true` is set **before** the token transfer, and the `safeTransfer` reverts the entire transaction when the recipient is blacklisted, the nonce is not permanently consumed — but the call will revert on every retry for the same reason.

There is no pull-based withdrawal mechanism on EVM (no separate `claim()` function), and there is no cancel/refund path on the NEAR side for outbound transfers. The transfer message stored on NEAR is never removed, and the burned/locked tokens are never returned to the user.

---

### Impact Explanation

A user whose EVM address is on the USDC (or USDT, or any transfer-restricted token) blacklist cannot receive bridged funds. The relayer cannot finalize the transfer — every call to `finTransfer` reverts. The user's tokens are already burned or locked on NEAR at the time of `initTransfer`. With no cancel mechanism on NEAR and no alternative claim path on EVM, the funds are permanently frozen. This satisfies the **Critical** impact criterion: permanent freezing of bridged funds.

---

### Likelihood Explanation

USDC and USDT are among the most commonly bridged assets. OFAC sanctions and Circle/Tether compliance actions regularly blacklist addresses. A user may be blacklisted **after** initiating a NEAR → EVM transfer but **before** the relayer finalises it on EVM. The window between `initTransfer` on NEAR and `finTransfer` on EVM is non-zero (relayer latency, MPC signing time). This is a realistic, externally-triggered condition requiring no privileged access.

---

### Recommendation

Replace the push-transfer pattern in `finTransfer` with a pull-based (claim) pattern:

1. Instead of calling `safeTransfer` inside `finTransfer`, record the claimable amount in a mapping: `claimable[payload.recipient][payload.tokenAddress] += payload.amount`.
2. Add a separate `claim(address tokenAddress)` function that lets the recipient (or any address they designate) withdraw their balance.
3. This decouples delivery failure from finalisation, ensuring the nonce is consumed and the transfer is recorded even if the recipient cannot currently receive the token.

---

### Proof of Concept

1. Alice holds USDC on NEAR and calls `initTransfer` to bridge 10,000 USDC to her EVM address `0xAlice`. USDC is burned on NEAR; a `TransferMessage` is stored.
2. Before the relayer finalises, Circle blacklists `0xAlice` (e.g., due to a sanctions designation).
3. The relayer calls `finTransfer` with the MPC-signed payload targeting `0xAlice`.
4. Execution reaches line 351: `IERC20(USDC).safeTransfer(0xAlice, 10000e6)` — USDC's `transfer` reverts because `0xAlice` is blacklisted.
5. The entire transaction reverts; `completedTransfers[nonce]` is not set.
6. Every subsequent retry by any relayer produces the same revert.
7. There is no `cancel` or refund function on NEAR for outbound transfers; the `TransferMessage` remains in storage indefinitely.
8. Alice's 10,000 USDC is permanently frozen — burned on NEAR, undeliverable on EVM.

**Root cause line references:** [1](#0-0) [2](#0-1) 

No cancel/refund path exists for outbound transfers on NEAR: [3](#0-2)

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

**File:** near/omni-bridge/src/lib.rs (L438-521)
```rust
    /// # Panics
    ///
    /// This function will panic under the following conditions:
    ///
    /// - If the `borsh::to_vec` serialization of the `TransferMessagePayload` fails.
    /// - If a `fee` is provided and it doesn't match the fee in the stored transfer message.
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
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
