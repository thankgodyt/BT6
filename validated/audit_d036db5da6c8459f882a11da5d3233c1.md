### Title
Missing Zero-Address Recipient Validation in `init_transfer` Allows Permanent Loss of Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `init_transfer` function in the NEAR `omni-bridge` contract accepts a user-supplied `recipient` field of type `OmniAddress` without checking whether it is a zero address. An `OmniAddress::is_zero()` helper exists but is never called at the entry point. A user who provides a zero EVM/Solana/Starknet address as recipient will have their tokens permanently locked or burned on NEAR with no recovery path.

---

### Finding Description

`init_transfer` is the internal handler invoked by `ft_on_transfer` when a user calls `ft_transfer_call` on a NEP-141 token with an `InitTransferMsg` payload. The only recipient-related validation performed is a chain-kind check: [1](#0-0) 

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
```

This rejects `ChainKind::Near` recipients but accepts any other `OmniAddress` value, including a zero EVM address such as `eth:0x0000000000000000000000000000000000000000`. The `OmniAddress` type already exposes an `is_zero()` predicate that covers all chain variants: [2](#0-1) 

but it is never invoked in `init_transfer`.

After the check passes, the transfer message is stored in `pending_transfers` and the user's tokens are either locked or burned on NEAR: [3](#0-2) 

A relayer then calls `sign_transfer`, which constructs a `TransferMessagePayload` with the zero recipient and requests an MPC signature: [4](#0-3) 

The signed payload is submitted to `finTransfer` on the EVM bridge. For native ETH (`tokenAddress == address(0)`), the contract executes: [5](#0-4) 

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
```

A low-level call to `address(0)` succeeds and the ETH is permanently burned. For ERC20 bridge tokens, `IBridgeToken.mint(address(0), amount)` reverts (OpenZeppelin ERC20 rejects minting to the zero address): [6](#0-5) 

leaving the NEAR-side tokens permanently locked with no refund or cancellation mechanism visible in the contract.

---

### Impact Explanation

- **Native ETH transfers**: ETH is irrecoverably sent to `address(0)` and burned.
- **ERC20 / bridge-token transfers**: `finTransfer` reverts on the EVM side; the corresponding tokens remain locked or burned on NEAR indefinitely because no `cancel_transfer` or refund path exists in the NEAR contract.

In both cases the user suffers a **permanent, total loss** of the bridged amount. This matches the "permanent freezing or loss of bridged funds" critical impact class.

---

### Likelihood Explanation

The entry point is fully unprivileged: any token holder can call `ft_transfer_call` with an arbitrary `msg` string. A zero EVM address is a realistic user mistake (e.g., a buggy frontend, a copy-paste error, or a developer testing). No admin compromise, key leak, or colluding validator is required.

---

### Recommendation

Add a zero-address guard immediately after the chain-kind check in `init_transfer`:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
require!(
    !init_transfer_msg.recipient.is_zero(),
    BridgeError::InvalidRecipient.as_ref()   // add a new error variant
);
```

Additionally, add a symmetric guard in `OmniBridge.sol`'s `finTransfer` as a defence-in-depth measure:

```solidity
require(payload.recipient != address(0), "InvalidRecipient");
```

---

### Proof of Concept

1. User holds 1 WETH bridged token on NEAR.
2. User calls `ft_transfer_call` on the WETH NEP-141 contract with:
   ```json
   {
     "receiver_id": "omni-bridge.near",
     "amount": "1000000000000000000",
     "msg": "{\"InitTransfer\":{\"recipient\":\"eth:0x0000000000000000000000000000000000000000\",\"fee\":\"0\",\"native_token_fee\":\"0\"}}"
   }
   ```
3. `ft_on_transfer` → `init_transfer` passes the chain-kind check (`Eth != Near`). No zero-address check fires. [1](#0-0) 
4. Tokens are burned on NEAR; transfer stored in `pending_transfers`.
5. Relayer calls `sign_transfer`; MPC signs a payload with `recipient = 0x000…000`. [4](#0-3) 
6. Relayer submits `finTransfer` on Ethereum. For a bridge token, `mint(address(0), amount)` reverts; for native ETH, `address(0).call{value}("")` succeeds and ETH is burned. [7](#0-6) 
7. No cancellation path exists on NEAR; funds are permanently lost.

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

**File:** near/omni-bridge/src/lib.rs (L531-534)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L540-557)
```rust
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
