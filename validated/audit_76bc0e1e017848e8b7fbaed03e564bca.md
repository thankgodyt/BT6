Audit Report

## Title
Unauthorized `fee_recipient` Specification in `sign_transfer` Allows Any Trusted Relayer to Steal Transfer Fees — (File: `near/omni-bridge/src/lib.rs`)

## Summary
`sign_transfer` accepts a fully caller-controlled `fee_recipient` parameter with no validation that the caller is the intended fee recipient. Because the transfer message remains in storage for any transfer with `fee > 0`, multiple trusted relayers can each obtain a valid MPC-signed payload for the same transfer with different `fee_recipient` values but the same `destination_nonce`. Whichever relayer submits their signature first on the destination chain wins the entire fee, stealing it from the legitimate relayer.

## Finding Description
In `near/omni-bridge/src/lib.rs` at L447–521, `sign_transfer` is gated by `#[trusted_relayer]` but places no constraint on the `fee_recipient` argument:

```rust
pub fn sign_transfer(
    &mut self,
    transfer_id: TransferId,
    fee_recipient: Option<AccountId>,   // fully caller-controlled
    fee: &Option<Fee>,
) -> Promise {
    let transfer_message = self.get_transfer_message(transfer_id);
    // ... no check that caller == fee_recipient
    let transfer_payload = TransferMessagePayload {
        ...
        fee_recipient,   // attacker's account embedded here
        ...
    };
    // MPC signs this payload
```

The callback at L648–668 only removes the transfer message when `fee.is_zero()`:

```rust
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
```

For any transfer with `fee > 0`, the transfer message persists in `pending_transfers` after a successful `sign_transfer` call. This means any other trusted relayer can call `sign_transfer` on the same `transfer_id` and embed their own account as `fee_recipient`, causing the MPC to produce a second valid signature over a different payload (same `destination_nonce`, different `fee_recipient`).

On the EVM destination (`OmniBridge.sol` L283–287), the nonce is marked used on the first `finTransfer` call:

```solidity
if (completedTransfers[payload.destinationNonce]) {
    revert NonceAlreadyUsed(payload.destinationNonce);
}
completedTransfers[payload.destinationNonce] = true;
```

The `feeRecipient` field is part of the Borsh-encoded payload that the MPC signature covers (L289–308), so the destination chain pays the fee to whoever is named in the winning signature. The legitimate relayer's signature is then permanently rejected with `NonceAlreadyUsed`.

The same nonce-based finalization applies on Starknet (`omni_bridge.cairo` L247–254) and Solana (`FinalizeTransferPayload.fee_recipient` is part of the signed message).

## Impact Explanation
This is a concrete fee mis-accounting issue that directly changes protocol-level balances. A malicious trusted relayer can steal the entire token fee (and native fee) from any pending NEAR-outbound transfer with `fee > 0`. The user's principal transfer completes correctly, but the fee is redirected from the legitimate relayer to the attacker. The legitimate relayer performs the work of monitoring and initiating the signing flow but receives zero compensation; the attacker gains the fee without having performed the work. This matches the allowed critical impact: **fee mis-accounting that changes user or protocol balances**.

## Likelihood Explanation
Becoming a trusted relayer requires staking 1,000 NEAR and waiting 7 days (the default `waiting_period_ns` of 604,800,000,000,000 ns). This is a meaningful but not prohibitive barrier. Once trusted, the attacker can target every pending transfer with a non-zero fee indefinitely. The attack requires only observing on-chain `InitTransferEvent` logs (public) and racing the legitimate relayer's `sign_transfer` call. Because `sign_transfer` is a separate step from `ft_on_transfer`, there is always a window between transfer creation and signing. The attack is repeatable across all pending transfers and requires no victim mistakes.

## Recommendation
1. **Bind `fee_recipient` to the caller**: Inside `sign_transfer`, enforce `fee_recipient == Some(env::predecessor_account_id())` (or derive it from the caller), so no relayer can name a different account as recipient.
2. **Alternatively, record the intended fee recipient at transfer creation time** in `TransferMessage` and enforce it in `sign_transfer`, rejecting any caller-supplied value that differs.
3. **Remove the transfer message on the first successful `sign_transfer` call regardless of fee**, preventing repeated signing attempts on the same transfer by different relayers.

## Proof of Concept
```
1. User calls ft_transfer_call → ft_on_transfer → init_transfer.
   Transfer stored: { transfer_id: T, fee: 100, ... }
   Event emitted: InitTransferEvent { transfer_id: T, ... }

2. Legitimate relayer R calls sign_transfer(T, fee_recipient=R, fee=...).
   MPC begins signing payload_R = { ..., fee_recipient: R, destination_nonce: N }.
   Transfer message NOT removed (fee > 0).

3. Attacker A (also a trusted relayer) observes the InitTransferEvent.
   A calls sign_transfer(T, fee_recipient=A, fee=...) in the same or next block.
   MPC begins signing payload_A = { ..., fee_recipient: A, destination_nonce: N }.
   (Transfer message still in storage because fee > 0.)

4. Both MPC signing requests complete. Two valid signatures exist:
   sig_R over payload_R  (fee → R)
   sig_A over payload_A  (fee → A)

5. A submits finTransfer(sig_A, payload_A) to EVM first.
   completedTransfers[N] = true.
   Recipient receives amount. Fee is paid to A.

6. R attempts finTransfer(sig_R, payload_R).
   Reverts: NonceAlreadyUsed(N).
   R receives nothing.
```

Reproducible as a local integration test: deploy the NEAR bridge contract on sandbox, register two trusted relayers R and A, initiate a transfer with non-zero fee, have both call `sign_transfer` with different `fee_recipient` values, verify both MPC signing callbacks succeed (transfer message still present), then simulate EVM `finTransfer` with A's payload first and confirm R's payload is rejected.