Audit Report

## Title
Unconstrained `fee_recipient` in `sign_transfer` Allows Any Trusted Relayer to Redirect Transfer Fees — (File: `near/omni-bridge/src/lib.rs`)

## Summary
`sign_transfer` accepts a caller-supplied `fee_recipient: Option<AccountId>` that is embedded verbatim into the MPC-signed `TransferMessagePayload` with no validation against any stored transfer state. Because the transfer message is not removed from `pending_transfers` after signing for non-zero-fee transfers, multiple trusted relayers can each obtain a distinct but cryptographically valid MPC signature for the same transfer with different `fee_recipient` values. Whoever submits their signature first to EVM `finTransfer` consumes the destination nonce and receives the fee, permanently invalidating all other signatures.

## Finding Description
`sign_transfer` is gated by `#[trusted_relayer]`, which is permissionlessly obtainable by any account that self-stakes the configured NEAR amount and survives the waiting period. The function accepts `fee_recipient: Option<AccountId>` and places it directly into `TransferMessagePayload` without any check against stored transfer state or the caller's identity:

```rust
// near/omni-bridge/src/lib.rs L491-500
let transfer_payload = TransferMessagePayload {
    ...
    fee_recipient,   // verbatim caller-supplied value
    ...
};
```

The payload is hashed and forwarded to the MPC signer, producing a signature that cryptographically commits to the attacker-chosen `fee_recipient`. The callback `sign_transfer_callback` only removes the transfer message when the fee is zero:

```rust
// near/omni-bridge/src/lib.rs L655-658
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
```

For any non-zero-fee transfer, the message remains in `pending_transfers`, so any number of trusted relayers can call `sign_transfer` for the same `transfer_id` with different `fee_recipient` values and each receive a valid MPC signature. On the EVM side, `finTransfer` marks `completedTransfers[payload.destinationNonce] = true` on first use and reverts with `NonceAlreadyUsed` on all subsequent calls, making all but the first-submitted signature permanently useless. The `feeRecipient` field is Borsh-encoded as part of the verified data, so the EVM pays the fee to whichever account was embedded in the winning signature.

The `TransferMessage` struct stored at initiation time contains no `fee_recipient` field — it is never recorded at `init_transfer` time — so there is no on-chain source of truth to validate against.

## Impact Explanation
This is a concrete fee mis-accounting impact: fees are paid to an attacker-controlled account instead of the legitimate relayer, changing both relayer and attacker balances on every targeted transfer. The user's principal transfer completes correctly (they receive `amount − fee` on the destination chain), but the legitimate relayer's fee revenue is permanently stolen. The destination nonce is consumed by the attacker's submission, making the legitimate relayer's subsequently obtained signature permanently invalid. This matches the Critical allowed impact: "fee mis-accounting... that changes user or protocol balances."

## Likelihood Explanation
Becoming a trusted relayer requires staking the configured NEAR amount (default 1,000 NEAR) and waiting the configured period (default 7 days). The stake is fully returned on voluntary `resign_trusted_relayer`, so the attacker's net cost is only gas. Any active bridge with non-trivial fee settings makes this profitable. The attacker can monitor the NEAR chain for pending transfers, call `sign_transfer` with `fee_recipient` set to their own account, and submit to EVM before the legitimate relayer. No privileged access, leaked keys, or external dependency failure is required. The DAO can reject or revoke a relayer application, but cannot prevent the attack if the attacker resigns before detection.

## Recommendation
Store `fee_recipient` inside `TransferMessage` at initiation time in `init_transfer` so it is fixed and cannot be overridden at signing time. Alternatively, enforce that the caller-supplied `fee_recipient` must equal `env::predecessor_account_id()` (i.e., the signing relayer can only designate themselves), or remove the transfer message from `pending_transfers` immediately upon successful signing regardless of fee amount to prevent multiple valid signatures from being generated for the same transfer.

## Proof of Concept
1. Attacker calls `apply_for_trusted_relayer` with the required stake deposit and waits for the waiting period to elapse.
2. User calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer`, creating a pending transfer with `fee = 100 tokens`. The `TransferMessage` stored in `pending_transfers` contains no `fee_recipient`.
3. Legitimate relayer calls `sign_transfer(transfer_id, fee_recipient = Some("relayer.near"), fee = ...)`. MPC produces signature S1 over `TransferMessagePayload { ..., fee_recipient: Some("relayer.near"), ... }`.
4. Attacker (also a trusted relayer) calls `sign_transfer(transfer_id, fee_recipient = Some("attacker.near"), fee = ...)`. Because the transfer message was not removed (non-zero fee), the call succeeds. MPC produces signature S2 over `TransferMessagePayload { ..., fee_recipient: Some("attacker.near"), ... }`.
5. Attacker submits S2 to EVM `finTransfer` first. `completedTransfers[destinationNonce]` is set to `true`. Fee is paid to `attacker.near`.
6. Legitimate relayer submits S1. EVM reverts with `NonceAlreadyUsed`. The legitimate relayer's fee is permanently lost.
7. Attacker calls `resign_trusted_relayer`, recovering their full stake. Net cost: gas only.