Audit Report

## Title
Asymmetric Burn/Lock in `fast_fin_transfer_to_other_chain` Causes Deployed-Token Supply Inflation — (File: `near/omni-bridge/src/lib.rs`)

## Summary
`fast_fin_transfer_to_other_chain` burns and locks only `amount_without_fee` for deployed tokens, while the `TransferMessage` it creates carries the full `amount` (including fee). When the relayer later calls `claim_fee`, `send_fee_internal` mints the fee amount for deployed tokens, leaving the fee portion permanently unburned in the bridge's balance and minting it a second time. Every fast transfer to a non-NEAR destination inflates the deployed-token supply by the fee amount.

## Finding Description
In `fast_fin_transfer_to_other_chain` (lines 928–938), only `amount_without_fee` is burned and locked:

```rust
let amount_without_fee = fast_transfer
    .amount_without_fee()
    .near_expect(BridgeError::InvalidFee);

self.burn_tokens_if_needed(fast_transfer.token_id.clone(), amount_without_fee.into());
self.lock_tokens_if_needed(
    fast_transfer.get_destination_chain(),
    &fast_transfer.token_id,
    amount_without_fee,
);
```

Yet the `TransferMessage` created immediately after (lines 947–957) carries `amount: fast_transfer.amount` — the full amount including fee. This is the value stored and later used by `claim_fee_callback` (line 1131):

```rust
let fee = transfer_message.amount.0 - denormalized_amount;
self.send_fee_internal(&transfer_message, fee_recipient, fee)
```

For deployed tokens, `send_fee_internal` mints the fee (consistent with the pattern at lines 1722–1726 in `fin_transfer_send_tokens_callback`):

```rust
if self.is_deployed_token(&token) {
    ext_token::ext(token)
        .with_static_gas(MINT_TOKEN_GAS)
        .mint(fee_recipient.clone(), transfer_message.fee.fee, None)
        .detach();
}
```

By contrast, `init_transfer_internal` (lines 1851–1857) correctly burns and locks the full `transfer_message.amount` before the `TransferMessage` is stored, so the subsequent fee mint is balanced by the prior full burn.

The root cause is that `fast_fin_transfer_to_other_chain` decomposes the amount before burning/locking but stores the full amount in the `TransferMessage`, breaking the invariant that every token accounted for in a `TransferMessage` has been burned or locked on NEAR.

## Impact Explanation
For each fast transfer of a deployed token to a non-NEAR chain with fee `F`:
- Bridge receives `amount` tokens from relayer.
- Burns only `amount - F` → `F` tokens remain unburned in bridge balance.
- Mints `F` tokens to relayer at claim time.
- Net: `F` extra tokens permanently in circulation (bridge holds `F` unburned + relayer receives `F` minted = `F` tokens above the correct post-burn supply).

This constitutes unauthorized minting of bridged assets, directly matching the allowed critical impact: *"unauthorized minting… of bridged funds"* and *"fee mis-accounting… that changes user or protocol balances."* Additionally, `locked_tokens` is understated by `F` per transfer, corrupting the supply-cap accounting for NEAR-origin tokens.

## Likelihood Explanation
Any active trusted relayer executing fast transfers to non-NEAR destinations triggers this path in normal operation — no malicious intent required. The only gate is `is_trusted_relayer` (line 756). Inflation accumulates passively with every such transfer. A malicious trusted relayer can amplify the effect by maximizing the fee relative to the transfer amount.

## Recommendation
In `fast_fin_transfer_to_other_chain`, replace `amount_without_fee` with `fast_transfer.amount.0` in both `burn_tokens_if_needed` and `lock_tokens_if_needed` calls, mirroring `init_transfer_internal`. This ensures the fee portion of deployed tokens is destroyed on NEAR before being re-minted at claim time, preserving the supply invariant.

## Proof of Concept
1. Deployed token `T` exists (bridge is its controller/minter).
2. Trusted relayer calls `ft_transfer_call` sending `1000 T` to the bridge with `FastFinTransferMsg { amount: 1000, fee: { fee: 100 }, recipient: <EVM address> }`.
3. `fast_fin_transfer_to_other_chain` runs: burns `900 T`, leaves `100 T` unburned in bridge balance, stores `TransferMessage { amount: 1000, fee: 100 }`.
4. Transfer finalizes on EVM; recipient receives `900 T` equivalent.
5. Relayer calls `claim_fee` with finalization proof.
6. `claim_fee_callback` computes `fee = 1000 - 900 = 100`, calls `send_fee_internal` → mints `100 T` to relayer.
7. Bridge holds `100 T` (never burned) + relayer holds `100 T` (freshly minted) = `100 T` net supply inflation per transfer.

A local integration test can confirm this by: (a) recording total supply before the sequence, (b) executing steps 2–6 against a localnet deployment, and (c) asserting `total_supply_after == total_supply_before - 900` (correct) vs observing `total_supply_after == total_supply_before - 800` (buggy) while the bridge account retains a non-zero `T` balance.