### Title
Missing Zero-Address Validation for `payload.recipient` in `finTransfer` Allows Permanent Loss of Native ETH — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.finTransfer` does not validate that `payload.recipient` is non-zero before dispatching funds. For the native-ETH branch (`payload.tokenAddress == address(0)`), ETH is sent directly to `payload.recipient` via a low-level `.call`. If `payload.recipient` is `address(0)`, the call succeeds silently and the ETH is permanently burned. The upstream NEAR `init_transfer` function also performs no `is_zero()` check on the recipient, so a user can legitimately submit a transfer destined for the zero address and the MPC will sign it.

---

### Finding Description

In `OmniBridge.finTransfer`, after signature verification, the contract dispatches funds to `payload.recipient` without any zero-address guard:

```solidity
if (payload.tokenAddress == address(0)) {
    // slither-disable-next-line arbitrary-send-eth
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [1](#0-0) 

A `.call` to `address(0)` always returns `success = true` in the EVM (the zero address has no code and accepts ETH). The `if (!success)` guard therefore does not protect against this case. The ETH is irrecoverably lost.

The upstream entry point on NEAR, `init_transfer`, only checks that the recipient chain is not NEAR — it does not call `recipient.is_zero()`:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
``` [2](#0-1) 

`OmniAddress::is_zero()` exists and is used elsewhere in the codebase, but is never called on the recipient at transfer-initiation time: [3](#0-2) 

Because the transfer message (including the zero recipient) is stored and then signed by the MPC, the resulting signature is valid. Any caller can then submit it to `finTransfer` on EVM.

---

### Impact Explanation

A user who mistakenly (or deliberately, to grief themselves) specifies `address(0)` as the EVM recipient for a native-ETH bridge transfer will have their ETH permanently destroyed. The nonce is marked completed (`completedTransfers[payload.destinationNonce] = true`) before the dispatch, so the transfer cannot be replayed or recovered. [4](#0-3) 

This constitutes permanent, irreversible loss of bridged funds — within the allowed impact scope.

Note: For ERC-20 bridge tokens and ERC-1155 tokens, OpenZeppelin's `safeTransfer` / `_mint` / `safeTransferFrom` internally revert on `address(0)`, so those branches are incidentally protected. The vulnerability is specific to the native-ETH branch.

---

### Likelihood Explanation

The attack path requires only a single unprivileged user action: calling `ft_transfer_call` on NEAR with `recipient = OmniAddress::Eth(H160::ZERO)`. No admin access, no key compromise, and no relayer collusion is needed. The MPC signs whatever is in the stored transfer message; it does not validate recipient addresses. The likelihood is realistic for user error and is a one-step mistake with no recovery path.

---

### Recommendation

1. **In `OmniBridge.finTransfer` (EVM):** Add an explicit guard before any fund dispatch:
   ```solidity
   if (payload.recipient == address(0)) revert InvalidRecipient();
   ```

2. **In `init_transfer` (NEAR):** Add a zero-address check on the recipient before storing the transfer message:
   ```rust
   require!(
       !init_transfer_msg.recipient.is_zero(),
       BridgeError::InvalidRecipientAddress.as_ref()
   );
   ``` [5](#0-4) 

Fixing at the NEAR layer prevents the MPC from ever signing a zero-recipient payload. Fixing at the EVM layer provides defense-in-depth for any path (including Wormhole or Starknet routes) that could produce a zero-recipient `finTransfer` call.

---

### Proof of Concept

1. User holds a NEAR-side token that maps to native ETH on EVM (i.e., `tokenAddress == address(0)` on EVM).
2. User calls `ft_transfer_call` on NEAR with:
   ```json
   { "recipient": "eth:0x0000000000000000000000000000000000000000", "fee": "0", "native_token_fee": "0" }
   ```
3. `init_transfer` accepts the message — the only recipient check (`get_chain() != Near`) passes. [2](#0-1) 
4. A relayer calls `sign_transfer`; the MPC signs the payload containing `recipient = 0x000...000`.
5. The relayer (or anyone) calls `finTransfer` on EVM with the signed payload where `payload.tokenAddress = address(0)` and `payload.recipient = address(0)`.
6. The branch `payload.tokenAddress == address(0)` is taken; `address(0).call{value: amount}("")` returns `success = true`; ETH is permanently lost. [1](#0-0) 
7. `completedTransfers[nonce]` is set to `true`; the transfer is finalized with no recovery possible. [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
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
