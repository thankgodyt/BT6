Audit Report

## Title
Missing Zero-Address Recipient Check in `init_transfer` Causes Permanent Freezing of Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

## Summary
The `init_transfer` function in `near/omni-bridge/src/lib.rs` validates the recipient's chain kind but never calls `recipient.is_zero()`, which is fully implemented in `near/omni-types/src/lib.rs`. Any token holder can initiate a transfer to the zero address of any EVM chain. Tokens are immediately locked or burned on NEAR, and because EVM `finTransfer` either destroys ETH permanently or always reverts for ERC-20/bridge tokens, no valid proof is ever produced. With no cancel or refund path in the NEAR contract, the funds are permanently frozen and `locked_tokens` is permanently inflated.

## Finding Description
**Root cause — `near/omni-bridge/src/lib.rs` lines 531–534:**

The only recipient validation is a chain-kind check:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
```

There is no subsequent call to `recipient.is_zero()`. The method is fully implemented in `near/omni-types/src/lib.rs` lines 299–313 and covers all chain variants (EVM, Solana, Starknet, BTC, Zcash, NEAR). The `InvalidRecipientAddress` error variant already exists in `near/omni-types/src/errors.rs` line 31.

After this check, `init_transfer_internal` is called, which at lines 1850–1864 locks or burns the user's tokens via `burn_tokens_if_needed` / `lock_tokens_if_needed` and emits `InitTransferEvent`. The transfer is stored in `pending_transfers` and `locked_tokens` is incremented.

**Destination-side behavior — `evm/src/omni-bridge/contracts/OmniBridge.sol` lines 317–355:**

`finTransfer` performs no zero-address check on `payload.recipient`:
- **Native ETH** (`tokenAddress == address(0)`): `address(0).call{value: amount}("")` succeeds in Solidity — ETH is permanently destroyed, nonce consumed, funds unrecoverable.
- **ERC-20 / bridge tokens**: OpenZeppelin's `safeTransfer` and `_mint` both revert on `address(0)`. Every relay attempt reverts; no valid proof is ever generated.

**No refund path:** A search for `cancel_transfer` and `refund_transfer` in `near/omni-bridge/src/lib.rs` returns no matches. The only path that calls `remove_transfer_message` (line 1094) is `claim_fee_callback`, which requires a valid proof from the destination chain. If `finTransfer` always reverts, no proof is produced, `claim_fee_callback` is never called, and the pending transfer entry and `locked_tokens` counter are never decremented.

## Impact Explanation
This is a **Critical** impact matching "permanent freezing of bridged funds." For ERC-20 and bridge tokens, user funds are permanently locked in the NEAR bridge contract with no recovery mechanism. For native ETH transfers, funds are permanently destroyed. Additionally, `locked_tokens[(destination_chain, token_id)]` is permanently inflated, causing escrow mis-accounting for the lifetime of the contract. The vulnerability is triggered entirely through public smart-contract calls by an unprivileged user.

## Likelihood Explanation
The entry point is `ft_transfer_call` → `ft_on_transfer` → `init_transfer`, callable by any token holder. Supplying `recipient = "eth:0x0000000000000000000000000000000000000000"` is syntactically valid and passes all existing checks. This can occur via a malicious or buggy frontend, a programmatic integration that passes user-supplied recipient data without sanitization, or deliberate self-burn. No privileged role is required. The attack is repeatable and affects any supported EVM chain's zero address.

## Recommendation
Add a zero-address guard immediately after the chain-kind check in `init_transfer` (`near/omni-bridge/src/lib.rs`):

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
require!(
    !init_transfer_msg.recipient.is_zero(),
    BridgeError::InvalidRecipientAddress.as_ref()
);
```

The `InvalidRecipientAddress` variant already exists. Apply equivalent guards in the EVM `initTransfer` (reject `address(0)` recipient) and Starknet `init_transfer` (reject zero `ContractAddress`).

## Proof of Concept
1. Alice holds 1,000 USDC bridged on NEAR.
2. Alice calls:
   ```
   ft_transfer_call(
     receiver_id = "omni-bridge.near",
     amount      = "1000000000",
     msg         = '{"InitTransfer":{"recipient":"eth:0x0000000000000000000000000000000000000000","fee":"0","native_token_fee":"0"}}'
   )
   ```
3. `init_transfer` passes the chain-kind check (`Eth != Near`), no `is_zero()` check fires. `init_transfer_internal` locks 1,000 USDC, stores the pending transfer, emits `InitTransferEvent`.
4. MPC service signs the `TransferMessage` containing `recipient = 0x0000…0000`.
5. Relayer submits `finTransfer` on Ethereum: `safeTransfer(address(0), amount)` reverts (OpenZeppelin guard). Every retry reverts.
6. No proof is ever produced. `claim_fee_callback` is never called. Alice's 1,000 USDC remain locked forever. `locked_tokens[(Eth, usdc.near)]` is permanently inflated.

**Test plan:** Write a NEAR integration test that calls `ft_transfer_call` with a zero-address EVM recipient, assert the transfer is stored in `pending_transfers` and `locked_tokens` is incremented, then assert no `claim_fee_callback` path can clear it without a valid proof — confirming permanent lock.