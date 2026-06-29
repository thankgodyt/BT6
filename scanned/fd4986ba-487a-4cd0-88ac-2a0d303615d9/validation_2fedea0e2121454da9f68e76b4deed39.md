### Title
Fee-on-Transfer Token Escrow Over-Crediting in `initTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.sol`'s `initTransfer` function calls `safeTransferFrom` with the caller-supplied `amount` and then unconditionally emits an `InitTransfer` event with that same `amount`. For fee-on-transfer ERC-20 tokens, the contract receives fewer tokens than `amount`, but the emitted event records the full `amount`. The NEAR bridge relayer uses this event to mint or unlock the full `amount` on NEAR, permanently over-crediting the recipient and leaving the EVM escrow undercollateralized.

### Finding Description
In `initTransfer`, the regular-token branch performs:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // caller-supplied
);
```

followed immediately by:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // same caller-supplied value, not actual received amount
    fee,
    nativeFee,
    recipient,
    message
);
```

No balance snapshot is taken before the transfer, and no comparison is made between the pre- and post-transfer balance of the contract. For a fee-on-transfer token, the contract receives `amount - transfer_fee` tokens, but the event records `amount`. The NEAR-side relayer reads the event and calls `fin_transfer` on NEAR, which mints or unlocks the full `amount` (after decimal denormalization) to the recipient. [1](#0-0) [2](#0-1) 

### Impact Explanation
The EVM bridge escrow is undercollateralized by `transfer_fee` tokens per such bridging operation. When any user later bridges the same token back from NEAR to EVM (triggering `finTransfer` on EVM, which calls `safeTransfer(recipient, amount)`), the bridge will either revert due to insufficient balance or drain tokens that belong to other users. Repeated exploitation drains the EVM escrow entirely for that token, causing permanent loss of bridged funds for honest users. This is a direct escrow mis-accounting / balance manipulation impact. [3](#0-2) 

### Likelihood Explanation
Any unprivileged user can call `initTransfer` with any ERC-20 token address — there is no whitelist enforced in the base `OmniBridge` contract. Fee-on-transfer tokens (e.g., tokens with a built-in deflationary mechanism or tokens that redirect a percentage to a treasury) are a well-known and deployed token class. A single call with such a token is sufficient to trigger the discrepancy. The attacker profits by receiving more tokens on NEAR than they deposited on EVM. [4](#0-3) 

### Recommendation
Record the contract's token balance before and after the `safeTransferFrom` call, and use the actual received amount in the event emission and all downstream accounting:

```solidity
} else {
    uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
    IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
    uint128 received = uint128(IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore);
    require(received == amount, "Fee-on-transfer tokens not supported");
    // or: use `received` instead of `amount` in the event and extension call
}
```

Alternatively, explicitly document and enforce a token whitelist that excludes fee-on-transfer tokens, reverting if an unlisted token is supplied.

### Proof of Concept
1. Deploy or use any ERC-20 token that deducts a 1% fee on every transfer (e.g., a deflationary token).
2. Approve `OmniBridge` for `1000` tokens.
3. Call `initTransfer(tokenAddress, 1000, 0, 0, "recipient.near", "")`.
4. The bridge receives `990` tokens (`safeTransferFrom` deducts 10 as fee).
5. The emitted `InitTransfer` event records `amount = 1000`.
6. The NEAR relayer submits the proof; `fin_transfer_callback` on NEAR mints `1000` tokens to `recipient.near`.
7. The EVM bridge now holds only `990` tokens but has issued a `1000`-token claim on NEAR.
8. When any user bridges `1000` tokens back from NEAR to EVM, `finTransfer` on EVM attempts `safeTransfer(recipient, 1000)` but only `990` tokens are available, causing a revert or draining another user's deposit. [1](#0-0) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-355)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-413)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-436)
```text
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

**File:** near/omni-bridge/src/lib.rs (L698-746)
```rust
    #[private]
    #[payable]
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
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

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
    }
```
