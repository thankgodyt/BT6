Audit Report

## Title
Missing Zero-Address Recipient Validation in `init_transfer` Causes Permanent Fund Loss - (File: near/omni-bridge/src/lib.rs)

## Summary
The `init_transfer` function in `near/omni-bridge/src/lib.rs` validates only that the recipient chain is not NEAR, but never checks whether the recipient address itself is a zero address. A user who specifies a zero-address recipient (e.g., `eth:0x0000000000000000000000000000000000000000`) causes tokens to be immediately locked or burned on NEAR. The resulting `finTransfer` call on EVM either permanently burns native ETH or permanently freezes ERC-20/bridge tokens with no recovery path.

## Finding Description
In `init_transfer`, the only recipient validation is a chain-kind check: [1](#0-0) 

No call to `is_zero()` is made. The `OmniAddress::is_zero()` method exists in `near/omni-types/src/lib.rs` and covers all supported chain types: [2](#0-1) 

The zero-address recipient is stored verbatim into `TransferMessage`: [3](#0-2) 

It is then embedded into `TransferMessagePayload` and signed by the NEAR MPC: [4](#0-3) 

On the EVM side, `finTransfer` in `OmniBridge.sol` has no zero-address guard on `payload.recipient`. For native ETH (`tokenAddress == address(0)`), the low-level call to `address(0)` succeeds silently, permanently burning ETH: [5](#0-4) 

For ERC-20 and bridge tokens, OpenZeppelin's `safeTransfer` and `mint` revert on a zero-address recipient. Because the entire transaction reverts, the `completedTransfers[payload.destinationNonce] = true` write at line 287 also reverts, so the nonce is never consumed and every subsequent relay attempt also reverts: [6](#0-5) 

No `cancel_transfer` or `revert_transfer` function exists in `near/omni-bridge/src/lib.rs`, confirming there is no recovery path for the locked/burned NEAR-side funds.

## Impact Explanation
This is a **Critical** impact: permanent, irrecoverable loss of bridged funds. For native ETH, funds are directly burned. For ERC-20/bridge tokens, funds are permanently frozen on NEAR with no mechanism to recover them. This matches the allowed impact class: *permanent freezing or loss of bridged funds across NEAR and EVM chains*.

## Likelihood Explanation
Any unprivileged bridge user can trigger this with a single `ft_transfer_call` specifying a zero-address recipient in `InitTransferMsg`. No special role, admin access, or external dependency failure is required. The exploit is repeatable for any token type and any amount.

## Recommendation
Add a zero-address guard immediately after the chain-kind check in `init_transfer`:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
require!(
    !init_transfer_msg.recipient.is_zero(),
    BridgeError::InvalidRecipient.as_ref()
);
```

The `is_zero()` method already exists on `OmniAddress` and covers all supported chain types. [2](#0-1) 

## Proof of Concept
1. Attacker holds 1 wETH (NEP-141) on NEAR.
2. Attacker calls `ft_transfer_call` on the wETH token contract targeting the NEAR bridge with:
   ```json
   {"InitTransfer": {"recipient": "eth:0x0000000000000000000000000000000000000000", "fee": "0", "native_token_fee": "0"}}
   ```
3. `ft_on_transfer` → `init_transfer` passes the chain-kind check (Eth ≠ Near) and stores the transfer with `recipient = OmniAddress::Eth(H160::ZERO)`. The 1 wETH is locked/burned on NEAR.
4. A relayer calls `sign_transfer`; the NEAR MPC signs a `TransferMessagePayload` with `recipient = 0x0000000000000000000000000000000000000000`.
5. The relayer calls `finTransfer` on the EVM `OmniBridge`:
   - **ERC-20 path**: `safeTransfer(address(0), amount)` reverts; the nonce write reverts with it; every subsequent relay attempt also reverts. The 1 wETH equivalent is permanently frozen on NEAR.
   - **Native ETH path**: `address(0).call{value: amount}("")` succeeds; ETH is permanently burned.
6. No cancellation or refund function exists in the NEAR bridge contract to recover the locked/burned tokens.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-288)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```
