### Title
Native Fee (ETH) Permanently Frozen in EVM Bridge When NEAR-Side `ft_transfer_call` Recipient Rejects Tokens - (File: near/omni-bridge/src/lib.rs)

### Summary

The `fin_transfer_send_tokens_callback` refund path in the NEAR omni-bridge contract handles the NEP-141 token correctly (burns/reverts it) when a recipient contract rejects tokens via `ft_transfer_call`, but silently discards the `native_fee` component. The ETH paid as `nativeFee` by the user on the EVM side is permanently frozen in `OmniBridge.sol` with no on-chain recovery path.

### Finding Description

When a user initiates a cross-chain transfer from EVM to NEAR with a non-zero `nativeFee` and a non-empty `message` field, the EVM bridge locks the ERC-20 tokens and retains the ETH (`nativeFee`) in the contract. On the NEAR side, `process_fin_transfer_to_near` calls `send_tokens` using `ft_transfer_call` (because `msg` is non-empty). If the recipient contract's `ft_on_transfer` returns `0` (rejecting the tokens), `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = true`.

Inside `fin_transfer_send_tokens_callback`, `is_refund_required` evaluates to `true`, and the refund branch executes:

```rust
// lines 1702-1718 — refund path
if Self::is_refund_required(is_ft_transfer_call) {
    self.burn_tokens_if_needed(token.clone(), ...);   // NEP-141 handled
    self.revert_lock_actions(&lock_actions);           // NEP-141 handled
    self.remove_fin_transfer(...);
    // ← native_fee is NEVER minted or returned here
}
``` [1](#0-0) 

The success path, by contrast, explicitly mints the wrapped native token to the fee recipient:

```rust
// lines 1736-1743 — success path only
if transfer_message.fee.native_fee.0 > 0 {
    let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());
    ext_token::ext(native_token_id)
        .with_static_gas(MINT_TOKEN_GAS)
        .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
        .detach();
}
```

<cite repo="Noahgrantyt/omni-bridge--012" path="near/omni-bridge/src/lib.rs

### Citations

**File:** near/omni-bridge/src/lib.rs (L1702-1718)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
```
