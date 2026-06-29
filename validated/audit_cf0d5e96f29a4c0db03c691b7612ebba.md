All code references check out. Let me verify one more detail about whether the destination chain finalizes transfers in a way that prevents double-finalization.

Audit Report

## Title
Fee Recipient Hijacking via Unbound `sign_transfer` — Any Trusted Relayer Can Steal Fees from Competing Relayers - (File: `near/omni-bridge/src/lib.rs`)

## Summary

`sign_transfer` imposes no binding between the calling relayer and the pending transfer: any trusted relayer may supply an arbitrary `fee_recipient` for any pending transfer. Because the transfer record is not removed or locked after a successful MPC signing when the fee is non-zero, a second trusted relayer can obtain an independent, valid MPC signature for the same transfer embedding a different `fee_recipient`. Whoever submits their signature to the destination chain first finalises the transfer with their chosen `fee_recipient` and collects the full fee, while the legitimate relayer's signature and gas are wasted.

## Finding Description

**Root cause — no caller-to-transfer binding and no post-sign lock:**

`sign_transfer` is gated solely by `#[trusted_relayer]`, which verifies only that the caller is *any* active trusted relayer. There is no check that the caller is the relayer who initiated or was assigned this transfer, and `fee_recipient` is accepted verbatim from the caller:

```rust
// near/omni-bridge/src/lib.rs L444-500
#[payable]
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn sign_transfer(
    &mut self,
    transfer_id: TransferId,
    fee_recipient: Option<AccountId>,   // fully caller-controlled
    fee: &Option<Fee>,
) -> Promise {
    let transfer_message = self.get_transfer_message(transfer_id);
    // No ownership / caller check
    ...
    let transfer_payload = TransferMessagePayload {
        ...
        fee_recipient,   // embedded verbatim into MPC-signed payload
        ...
    };
```

After the MPC signs the payload, `sign_transfer_callback` removes the transfer record **only when the fee is zero**:

```rust
// near/omni-bridge/src/lib.rs L655-658
if let Ok(signature) = call_result {
    if fee.is_zero() {
        self.remove_transfer_message(message_payload.transfer_id);
    }
```

When the fee is non-zero the transfer remains in `pending_transfers`, fully open for any other trusted relayer to call `sign_transfer` again with a different `fee_recipient`, obtaining a second valid MPC signature for the same transfer.

**Destination-chain enforcement does not prevent the attack:**

On EVM, `finTransfer` prevents replay via `completedTransfers[payload.destinationNonce]` and verifies the MPC signature over the full payload including `feeRecipient`. This means only one of the two competing signatures can be accepted — whichever is submitted first. The `destinationNonce` is then marked used, making the second signature permanently worthless. The winning `feeRecipient` is emitted in the `FinTransfer` event.

**NEAR-side `claim_fee` enforces `fee_recipient == predecessor_account_id`**, but this check is satisfied by whoever holds the winning proof from the destination chain:

```rust
// near/omni-bridge/src/lib.rs L1083-1086
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
```

## Impact Explanation

This is concrete **fee mis-accounting**: fees are redirected from the legitimate relayer to a malicious trusted relayer. The malicious relayer calls `sign_transfer` with `fee_recipient = self`, obtains a valid MPC signature, submits it to the destination chain before the legitimate relayer, and then calls `claim_fee` on NEAR to collect the full fee. The legitimate relayer's signature is invalidated by the used nonce and they receive nothing. This directly changes relayer balances and matches the "Balance manipulation / fee mis-accounting" critical impact class.

## Likelihood Explanation

Becoming a trusted relayer requires staking 1,000 NEAR and waiting the `waiting_period_ns` (default ~7 days). Once active, the attack requires only monitoring public NEAR chain state for pending transfers with non-zero fees and issuing `sign_transfer` calls before or concurrently with the legitimate relayer. The stake is recoverable on resignation, so the net cost is only the opportunity cost of locked NEAR plus MPC signing gas. For a bridge handling significant volume, expected fee income far exceeds this cost, making the attack economically rational and repeatable across every fee-bearing pending transfer.

## Recommendation

1. **Bind `fee_recipient` to `env::predecessor_account_id()`**: Remove the caller-supplied `fee_recipient` parameter from `sign_transfer` and always use the signing relayer's account ID, preventing redirection to arbitrary accounts.
2. **Lock the transfer after the first `sign_transfer`**: Record the `fee_recipient` chosen by the first signer and reject subsequent `sign_transfer` calls for the same `transfer_id` unless the fee is zero.
3. **Remove the transfer record immediately on signing regardless of fee**: Rely on the destination-chain proof submitted via `claim_fee` to settle the fee, so no second signer can race.

## Proof of Concept

1. User initiates a NEAR → EVM transfer with `fee = 1000` tokens via `ft_transfer_call` → `init_transfer`. Transfer record is stored in `pending_transfers` with a non-zero fee.
2. Legitimate Relayer L calls `sign_transfer(transfer_id, fee_recipient = L, fee)`. MPC signs payload_L with `fee_recipient = L`. Transfer record **remains** in `pending_transfers` because `fee != 0` (confirmed at `sign_transfer_callback` L656-658).
3. Malicious Relayer M (also a trusted relayer) calls `sign_transfer(transfer_id, fee_recipient = M, fee)`. No ownership check exists; MPC signs payload_M with `fee_recipient = M`. This succeeds because the transfer is still in `pending_transfers` and there is no lock.
4. M submits payload_M with their signature to the EVM `OmniBridge.finTransfer`. The `destinationNonce` is marked used (`completedTransfers[nonce] = true`), tokens are transferred to the recipient, and a `FinTransfer` event is emitted with `feeRecipient = M`.
5. L attempts to submit payload_L — `finTransfer` reverts with `NonceAlreadyUsed`. L's signature is permanently worthless.
6. M calls `claim_fee` on NEAR with the EVM proof. `claim_fee_callback` verifies `fee_recipient == predecessor_account_id` (L1083-1086), which passes for M. M receives 1000 tokens. L receives nothing.