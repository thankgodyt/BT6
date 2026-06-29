### Title
Deflationary ERC20 Token Mis-Accounting in `initTransfer` Allows Bridge Reserve Drain - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` uses the caller-supplied `amount` parameter in the emitted `InitTransfer` event without verifying the actual number of tokens received by the contract. For deflationary ERC20 tokens, the contract receives fewer tokens than `amount`, but the event records `amount`. The NEAR bridge's `fin_transfer_callback` reads this event via proof and mints/releases the full `amount` to the recipient on NEAR, creating a permanent deficit in the EVM bridge's locked reserves.

---

### Finding Description

In `initTransfer`, when the token is neither a bridge token nor a custom-minter token, the contract locks the token via:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount
);
``` [1](#0-0) 

Immediately after, the function emits the event using the original caller-supplied `amount`, not the actual balance delta:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,   // <-- original param, not actual received
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

The same unchecked `amount` is also encoded into the Wormhole VAA payload in `OmniBridgeWormhole.initTransferExtension`: [3](#0-2) 

On the NEAR side, `fin_transfer_callback` decodes the proof and constructs the `TransferMessage` using `init_transfer.amount` directly from the proof (which was derived from the EVM event):

```rust
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
``` [4](#0-3) 

There is no balance-before/balance-after check anywhere in `initTransfer` to verify the actual tokens received. [5](#0-4) 

---

### Impact Explanation

For every deflationary ERC20 transfer from EVM to NEAR:

- EVM bridge locks `amount - deflation_fee` tokens.
- NEAR bridge mints/releases `amount` tokens to the recipient.
- The bridge's EVM-side reserve is short by `deflation_fee` per transfer.

After enough transfers, the EVM bridge cannot honor withdrawal requests from legitimate users who previously bridged tokens back from NEAR, because the contract holds fewer tokens than the total outstanding claims. This constitutes a permanent, cumulative loss of bridged funds for other users — a critical escrow mis-accounting impact.

---

### Likelihood Explanation

Any user can call `initTransfer` with a deflationary ERC20 token that is registered as a native (non-bridge, non-custom-minter) token. No special role or privilege is required. The attacker simply calls `initTransfer` repeatedly with a deflationary token to drain the reserve incrementally. The entry path is fully permissionless and externally reachable.

---

### Recommendation

Measure the actual received amount using a balance check before and after the `safeTransferFrom`, and use the delta as the canonical amount for the event and all downstream accounting:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// Use actualReceived instead of amount in the event and fee validation
```

The `fee >= amount` check and the event emission must both use `actualReceived` to remain consistent.

---

### Proof of Concept

1. A deflationary ERC20 token `DEFLT` (2% burn-on-transfer) is registered as a native token in the bridge (not a bridge token, not a custom minter).
2. Attacker calls `initTransfer(DEFLT, 1000, 0, 0, "near:recipient", "")`.
3. `safeTransferFrom` moves 1000 DEFLT from attacker; bridge receives 980 DEFLT (2% burned).
4. `InitTransfer` event is emitted with `amount = 1000`.
5. Relayer submits proof to NEAR `fin_transfer`; `fin_transfer_callback` reads `amount = 1000` from proof and mints 1000 NEAR-side tokens to recipient.
6. Recipient bridges 1000 tokens back to EVM; NEAR burns 1000 tokens and signs a release of 1000 DEFLT on EVM.
7. EVM bridge only holds 980 DEFLT but must release 1000 — the release fails or drains tokens belonging to other depositors.
8. Repeating step 2–5 accumulates the deficit, eventually making the bridge insolvent for all DEFLT depositors. [6](#0-5) [7](#0-6)

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L129-141)
```text
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.InitTransfer)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(sender),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeUint64(originNonce),
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
            Borsh.encodeUint128(nativeFee),
            Borsh.encodeString(recipient),
            Borsh.encodeString(message)
        );
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
