### Title
Missing Zero-Address Validation on Transfer Recipient Permanently Freezes Bridged ERC-20 Funds - (`near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR `init_transfer` function accepts any `OmniAddress` recipient without checking whether it is the zero address. A user who initiates a NEAR → EVM transfer with `recipient = OmniAddress::Eth(H160::ZERO)` locks their tokens in the NEAR bridge permanently: every subsequent `finTransfer` call on the EVM side reverts because OpenZeppelin ERC-20 and ERC-1155 contracts reject transfers to `address(0)`. No refund or cancellation path exists on NEAR, so the funds are frozen forever.

---

### Finding Description

`init_transfer` in `near/omni-bridge/src/lib.rs` performs exactly one recipient-side validation:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
``` [1](#0-0) 

It does **not** call `recipient.is_zero()`, even though that helper is fully implemented in the type system:

```rust
pub fn is_zero(&self) -> bool {
    match self {
        Self::Eth(address) | Self::Arb(address) | ... => address.is_zero(),
        ...
    }
}
``` [2](#0-1) 

After passing this single check, the zero-address recipient is stored verbatim in a `TransferMessage`:

```rust
let transfer_message = TransferMessage {
    ...
    recipient: init_transfer_msg.recipient,   // OmniAddress::Eth(H160::ZERO)
    ...
};
``` [3](#0-2) 

`sign_transfer` later reads this stored recipient and includes it in the MPC-signed `TransferMessagePayload` without any additional validation:

```rust
let transfer_payload = TransferMessagePayload {
    ...
    recipient: transfer_message.recipient,   // still address(0)
    ...
};
``` [4](#0-3) 

On the EVM side, `finTransfer` then attempts:

- **Bridge token path:** `IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount)` — OZ `_mint` reverts on `account == address(0)`.
- **Regular ERC-20 path:** `IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount)` — OZ `_transfer` reverts on `to == address(0)`.
- **ERC-1155 path:** `safeTransferFrom(address(this), address(0), ...)` — OZ reverts on `to == address(0)`. [5](#0-4) 

Because the nonce is marked used and the transfer message is removed from NEAR storage after signing (when `fee.is_zero()`), and because there is no public cancellation or refund entrypoint on NEAR, the tokens are permanently frozen. [6](#0-5) 

---

### Impact Explanation

Any ERC-20 or ERC-1155 token bridged from NEAR to an EVM chain with `recipient = address(0)` is permanently locked in the NEAR bridge contract. The MPC signature is valid, the destination nonce is consumed, and every relay attempt on EVM reverts. There is no on-chain recovery path. This constitutes **permanent freezing of bridged funds**, which is explicitly in scope.

---

### Likelihood Explanation

The entry point is `ft_on_transfer` on NEAR, callable by any token holder. A user need only supply `"eth:0x0000000000000000000000000000000000000000"` (or the equivalent for Arb, Base, Bnb, Pol, Abs, HyperEvm) as the recipient string. No special role or privilege is required. Accidental misuse (e.g., a dApp bug that passes an uninitialized address) is a realistic path in addition to deliberate exploitation.

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
    BridgeError::InvalidRecipient.as_ref()   // add this error variant
);
``` [1](#0-0) 

The same guard should be applied to the EVM `initTransfer` for completeness (the `recipient` string can be validated off-chain by the relayer, but an on-chain check is stronger):

```solidity
require(bytes(recipient).length > 0, "InvalidRecipient");
``` [7](#0-6) 

---

### Proof of Concept

1. Alice holds 1000 USDC (a registered ERC-20) on NEAR as a NEP-141 token.
2. Alice calls `ft_transfer_call` on the USDC NEP-141 contract, transferring 1000 tokens to the NEAR bridge with message `{"InitTransfer": {"recipient": "eth:0x0000000000000000000000000000000000000000", "fee": "0", "native_token_fee": "0"}}`.
3. `init_transfer` passes the only check (`get_chain() != Near`) and stores the transfer with `recipient = OmniAddress::Eth(H160::ZERO)`. [1](#0-0) 
4. A relayer calls `sign_transfer`. The MPC signs a `TransferMessagePayload` containing `recipient = 0x0000...0000`. The transfer message is removed from NEAR storage. [6](#0-5) 
5. The relayer submits `finTransfer` on Ethereum. The signature is valid. The contract reaches `IERC20(payload.tokenAddress).safeTransfer(address(0), 1000)`, which reverts with `ERC20InvalidReceiver`. [8](#0-7) 
6. Every retry of step 5 reverts identically. Alice's 1000 USDC are permanently locked in the NEAR bridge with no recovery path.

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

**File:** near/omni-bridge/src/lib.rs (L540-553)
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
```

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-355)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-384)
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
```
