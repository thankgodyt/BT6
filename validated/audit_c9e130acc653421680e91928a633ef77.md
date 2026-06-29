### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` records the caller-supplied `amount` in the `InitTransfer` event without verifying the actual amount received by the contract. For fee-on-transfer ERC-20 tokens the bridge holds less than `amount`, yet NEAR mints `amount` tokens, creating an unbacked supply and enabling fund theft.

---

### Finding Description

In `initTransfer`, when the token is neither a bridge token nor a custom-minter token, the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // caller-controlled
);
```

and immediately emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // same caller-controlled value, not actual received
    fee,
    nativeFee,
    recipient,
    message
);
``` [1](#0-0) 

`safeTransferFrom` only checks that `transferFrom` returns `true`; it does not verify the contract's balance delta. For a fee-on-transfer token the bridge receives `amount − transfer_fee`, but the event records `amount`.

The NEAR `fin_transfer_callback` reads the prover result and calls `denormalize_amount` on `init_transfer.amount` — the value from the event — then mints or unlocks that full amount for the recipient: [2](#0-1) 

The same pattern exists on Starknet's `init_transfer`: [3](#0-2) 

---

### Impact Explanation

An attacker who uses a registered fee-on-transfer token receives more wrapped tokens on NEAR than the EVM escrow actually holds. When those excess tokens are bridged back, the bridge must pay out from reserves deposited by other users, causing direct loss of funds. This is a classic escrow mis-accounting / unauthorized minting impact.

---

### Likelihood Explanation

Any ERC-20 token registered in the bridge that carries a transfer fee (reflection tokens, tokens with upgradeable fee switches, or tokens whose fee is activated post-registration) triggers the bug. The attacker needs no special role — only a registered token and the ability to call the public `initTransfer` function.

---

### Recommendation

Measure the actual received amount by snapshotting the contract balance before and after `safeTransferFrom`, and use the delta — not the caller-supplied `amount` — in the emitted event:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint128 received = uint128(IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore);
// use `received` in the event and downstream accounting
```

Apply the same fix to the Starknet `init_transfer`.

---

### Proof of Concept

1. A fee-on-transfer token (1 % fee) is registered in the bridge via `deploy_token` / `log_metadata`.
2. Attacker calls `initTransfer(tokenAddress, 1_000_000, 0, 0, "attacker.near", "")`.
3. Bridge receives `990_000` tokens; event records `amount = 1_000_000`.
4. Relayer submits proof to NEAR; `fin_transfer_callback` mints `1_000_000` wrapped tokens for the attacker.
5. Attacker calls NEAR `ft_transfer_call` to bridge `1_000_000` tokens back to EVM.
6. `sign_transfer` normalises and signs a payload for `1_000_000` tokens.
7. EVM `finTransfer` unlocks `1_000_000` tokens from escrow — `10_000` more than were ever deposited — draining funds belonging to other users. [4](#0-3) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L394-436)
```text
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
```

**File:** near/omni-bridge/src/lib.rs (L475-496)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L722-732)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };
```

**File:** near/omni-bridge/src/lib.rs (L1122-1133)
```rust
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
```

**File:** starknet/src/omni_bridge.cairo (L303-330)
```text
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }

            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }

            self
                .emit(
                    Event::InitTransfer(
                        InitTransfer {
                            sender: caller,
                            token_address,
                            origin_nonce,
                            amount,
                            fee,
                            native_fee,
                            recipient,
                            message,
                        },
                    ),
                )
```
