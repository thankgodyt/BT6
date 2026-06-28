### Title
Unvalidated Zero EVM Recipient Address Causes Permanent Freezing of Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

### Summary
A user initiating a NEAR→EVM transfer can specify `address(0)` as the EVM recipient. Tokens are locked on NEAR, but the EVM `finTransfer` call reverts because ERC20 tokens cannot be minted or transferred to `address(0)`. Since the MPC-signed payload encodes `recipient = address(0)` and cannot be changed without a new signature, the tokens are permanently frozen in the NEAR bridge contract with no recovery path.

### Finding Description
In `init_transfer` on NEAR (invoked via `ft_transfer_call`), the only recipient validation is:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
``` [1](#0-0) 

There is no check that the EVM recipient address is non-zero. `OmniAddress::is_zero()` exists in the type system but is never called here. [2](#0-1) 

A user can pass `recipient = "eth:0x0000000000000000000000000000000000000000"` in the `InitTransferMsg`. The tokens are locked on NEAR. The relayer then calls `sign_transfer`, which builds a `TransferMessagePayload` with `recipient = address(0)` and requests an MPC signature over it. [3](#0-2) 

When the relayer submits this signed payload to EVM `finTransfer`, the call reverts because `BridgeToken` inherits OpenZeppelin's `ERC20Upgradeable`, whose `_mint` rejects `address(0)`: [4](#0-3) 

For non-bridge ERC20 tokens, `safeTransfer(address(0), amount)` similarly reverts. The `completedTransfers[payload.destinationNonce] = true` write is rolled back by the revert, so the nonce is not consumed. However, the signed payload is permanently bound to `recipient = address(0)` — any re-signing via `sign_transfer` on the same `transfer_id` produces the same payload because the stored `TransferMessage.recipient` is `address(0)`. There is no cancel or admin-recovery function for `pending_transfers` in the NEAR contract. [5](#0-4) 

For native ETH transfers (`payload.tokenAddress == address(0)`), the outcome is worse: `address(0).call{value: payload.amount}("")` succeeds and the ETH is permanently burned. [6](#0-5) 

### Impact Explanation
Permanent freezing (ERC20/bridge tokens) or permanent burning (native ETH) of bridged user funds. The user's tokens are locked on NEAR with no on-chain recovery path, matching the allowed scope: *"permanent freezing of bridged funds across NEAR, EVM…"*

### Likelihood Explanation
Medium. The entry path is fully unprivileged — any user can call `ft_transfer_call` on NEAR. A user may accidentally or intentionally supply a zero EVM address. No validation exists at any layer (NEAR `init_transfer`, MPC signing, or EVM `finTransfer`) to reject it before funds are committed.

### Recommendation
Add a zero-address guard in `init_transfer` immediately after the chain-kind check:

```rust
require!(
    !init_transfer_msg.recipient.is_zero(),
    BridgeError::InvalidRecipient.as_ref()
);
``` [7](#0-6) 

Optionally, add a corresponding guard in EVM `finTransfer`:

```solidity
if (payload.recipient == address(0)) revert InvalidRecipient();
``` [8](#0-7) 

### Proof of Concept

1. User calls `ft_transfer_call` on NEAR with:
   ```json
   {"InitTransfer": {"recipient": "eth:0x0000000000000000000000000000000000000000", "fee": "0", ...}}
   ```
2. `init_transfer` validates `recipient.get_chain() != ChainKind::Near` → `Eth != Near` → **passes**.
3. Tokens are locked on NEAR; `TransferMessage { recipient: OmniAddress::Eth(H160::ZERO), ... }` is stored in `pending_transfers`.
4. Trusted relayer calls `sign_transfer(transfer_id, fee_recipient, fee)` → MPC signs `TransferMessagePayload` with `recipient = 0x000…000`.
5. Relayer submits signed payload to EVM `finTransfer`.
6. EVM executes `IBridgeToken(tokenAddress).mint(address(0), amount)` → **reverts** ("ERC20: mint to the zero address").
7. Transaction reverts; nonce not consumed. Re-signing produces the same payload. Tokens are **permanently frozen** on NEAR.

### Citations

**File:** near/omni-bridge/src/lib.rs (L491-500)
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
```

**File:** near/omni-bridge/src/lib.rs (L531-557)
```rust
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

**File:** near/omni-types/src/lib.rs (L299-313)
```rust
    pub fn is_zero(&self) -> bool {
        match self {
            Self::Eth(address)
            | Self::Arb(address)
            | Self::Base(address)
            | Self::Bnb(address)
            | Self::Pol(address)
            | Self::HyperEvm(address)
            | Self::Abs(address) => address.is_zero(),
            Self::Near(address) => *address == ZERO_ACCOUNT_ID,
            Self::Sol(address) | Self::Fogo(address) => address.is_zero(),
            Self::Btc(address) | Self::Zcash(address) => address.is_empty(),
            Self::Strk(address) => address.is_zero(),
        }
    }
```

**File:** evm/src/omni-bridge/contracts/BridgeToken.sol (L50-52)
```text
    function mint(address beneficiary, uint256 amount) external onlyOwner {
        _mint(beneficiary, amount);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-315)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-355)
```text
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
