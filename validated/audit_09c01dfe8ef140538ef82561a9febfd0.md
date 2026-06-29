Audit Report

## Title
Missing Zero-Address Validation on Transfer Recipient Permanently Freezes Bridged ERC-20 Funds - (File: near/omni-bridge/src/lib.rs)

## Summary
The `init_transfer` function in `near/omni-bridge/src/lib.rs` validates only that the recipient chain is not NEAR, but never checks whether the recipient address is the zero address. A user who initiates a NEAR→EVM transfer with `recipient = OmniAddress::Eth(H160::ZERO)` causes their tokens to be permanently locked: after MPC signing removes the transfer message from NEAR storage, every subsequent `finTransfer` call on the EVM side reverts because OpenZeppelin's `_mint` and `_transfer` reject `address(0)` as a recipient, and no on-chain cancellation or refund path exists.

## Finding Description
`init_transfer` performs exactly one recipient-side validation:

```rust
// near/omni-bridge/src/lib.rs L531-534
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
```

It does not call `recipient.is_zero()`, even though that helper is fully implemented in `near/omni-types/src/lib.rs` (L299-313) and covers all EVM chain variants (`Eth`, `Arb`, `Base`, `Bnb`, `Pol`, `HyperEvm`, `Abs`).

The zero-address recipient is stored verbatim in `TransferMessage` (L540-553) and later propagated into `TransferMessagePayload` in `sign_transfer` (L491-500) without any additional validation. After the MPC signs the payload, `sign_transfer_callback` removes the transfer message from NEAR storage when `fee.is_zero()` (L655-657), eliminating any on-chain record of the transfer on NEAR.

On the EVM side, `finTransfer` in `OmniBridge.sol` (L337-355) then attempts:
- `IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount)` — OZ `_mint` reverts on `account == address(0)`
- `IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount)` — OZ `_transfer` reverts on `to == address(0)`

The MPC signature is valid, the destination nonce is consumed, and every relay attempt reverts identically. No public cancellation or refund entrypoint exists on NEAR, so the funds are permanently frozen.

## Impact Explanation
This constitutes **permanent freezing of bridged funds**, which is explicitly listed as a Critical impact in the allowed scope. Any ERC-20 or ERC-1155 token bridged from NEAR to an EVM chain with `recipient = address(0)` is irrecoverably locked in the NEAR bridge contract. The impact is not hypothetical: the EVM revert is deterministic and the NEAR-side state is already cleared.

## Likelihood Explanation
The entry point is `ft_transfer_call` on any registered NEP-141 token, callable by any token holder with no special role or privilege. The attacker (or a victim of a dApp bug passing an uninitialized address) need only supply `"eth:0x0000000000000000000000000000000000000000"` as the recipient string. The condition is trivially reachable and repeatable for any of the seven supported EVM chains.

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

The same guard should be applied symmetrically to the EVM `initTransfer` for defense-in-depth:

```solidity
require(recipient != address(0), "InvalidRecipient");
```

## Proof of Concept
1. Alice holds 1000 USDC (registered NEP-141) on NEAR.
2. Alice calls `ft_transfer_call` on the USDC contract, transferring 1000 tokens to the NEAR bridge with message `{"InitTransfer": {"recipient": "eth:0x0000000000000000000000000000000000000000", "fee": "0", "native_token_fee": "0"}}`.
3. `init_transfer` passes the only check (`get_chain() != Near`) and stores the transfer with `recipient = OmniAddress::Eth(H160::ZERO)`.
4. A relayer calls `sign_transfer`. The MPC signs a `TransferMessagePayload` containing `recipient = 0x0000...0000`. Because `fee.is_zero()`, `sign_transfer_callback` calls `remove_transfer_message`, erasing the NEAR-side record.
5. The relayer submits `finTransfer` on Ethereum. The signature is valid. The contract reaches `IERC20(payload.tokenAddress).safeTransfer(address(0), 1000)`, which reverts with `ERC20InvalidReceiver`.
6. Every retry of step 5 reverts identically. Alice's 1000 USDC are permanently locked with no recovery path.