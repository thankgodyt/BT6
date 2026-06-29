### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary
`OmniBridge.sol`'s `initTransfer` function performs a `safeTransferFrom` for the user-specified `amount` and then unconditionally emits an `InitTransfer` event crediting that same `amount`. For fee-on-transfer ERC20 tokens, the contract receives fewer tokens than `amount`, but the NEAR bridge processes the event and mints/unlocks the full `amount` on the destination chain. This creates a growing escrow deficit that eventually prevents later users from withdrawing their funds.

---

### Finding Description

In `initTransfer`, when the token is a plain ERC20 (not a bridge token, not a custom minter), the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // user-specified, not verified against actual receipt
);
``` [1](#0-0) 

Immediately after, the contract emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // ← the user-specified amount, not actual received amount
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

There is no before/after `balanceOf` check to determine the real amount received. The `InitTransfer` event is the authoritative signal consumed by the NEAR bridge's proof system to credit the user on the destination chain. [3](#0-2) 

On the NEAR side, `fin_transfer_callback` reads the proven `init_transfer.amount` directly from the prover result and uses it to mint or unlock tokens for the recipient — it has no mechanism to cross-check the EVM contract's actual token balance. [4](#0-3) 

---

### Impact Explanation

For every `initTransfer` call with a fee-on-transfer ERC20 token:

- The EVM bridge contract receives `amount − fee_amount` tokens.
- The NEAR bridge mints/unlocks `amount` tokens for the user.
- The EVM escrow is short by `fee_amount` per transfer.

After N such transfers the bridge holds a cumulative deficit. When later users attempt to bridge back (triggering `finTransfer` on EVM, which calls `safeTransfer(recipient, amount)`), the contract will revert or drain reserves belonging to other depositors, causing permanent loss of funds for those users. This is a classic escrow undercollateralization attack. [5](#0-4) 

---

### Likelihood Explanation

Several ERC20 tokens already implement transfer fees (e.g., STA, PAXG, and various DeFi tokens). USDT has a fee mechanism that is currently set to zero but can be enabled by its owner. Any such token that is registered with the bridge (via `logMetadata` / `deployToken` flow, which is permissionless for the metadata step) becomes an attack vector. An unprivileged user only needs to call the public `initTransfer` function with a fee-bearing token to trigger the mis-accounting. [6](#0-5) 

---

### Recommendation

Record the contract's token balance before and after the `safeTransferFrom` and use the difference as the canonical `amount` for the emitted event:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualAmount = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualAmount in the event and downstream logic
```

Apply the same pattern to `finTransfer` (outbound transfer to recipient) to ensure the amount debited from the bridge's accounting matches what the recipient actually receives.

---

### Proof of Concept

1. Deploy or identify a fee-on-transfer ERC20 token (e.g., 1% fee per transfer) that is registered with the bridge.
2. Call `initTransfer(tokenAddress, 1000, 0, 0, nearRecipient, "")` with `amount = 1000`.
3. The bridge receives `990` tokens (1% fee deducted by the token contract).
4. The `InitTransfer` event is emitted with `amount = 1000`.
5. A relayer submits the proof to the NEAR bridge; `fin_transfer_callback` mints `1000` tokens to `nearRecipient`.
6. Repeat: after 100 such transfers the bridge holds `99,000` tokens but has issued `100,000` on NEAR — a `1,000`-token deficit.
7. The 100th user to bridge back to EVM finds the contract cannot pay out their full amount; funds are permanently lost. [7](#0-6)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-437)
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L700-746)
```rust
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
