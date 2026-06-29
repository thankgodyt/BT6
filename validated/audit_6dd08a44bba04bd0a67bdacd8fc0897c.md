Audit Report

## Title
Unbound `fee_recipient` in `sign_transfer` Allows Any Trusted Relayer to Steal Bridge Fees - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`sign_transfer` accepts a caller-controlled `fee_recipient: Option<AccountId>` parameter with no binding to `env::predecessor_account_id()`. Any registered trusted relayer can call `sign_transfer` on any pending `TransferMessage`, designate their own account as `fee_recipient`, obtain a valid MPC signature encoding that recipient, submit it to the destination chain, and then call `claim_fee` to collect the fee — stealing it from the relayer who legitimately initiated the transfer.

## Finding Description
`sign_transfer` is gated by `#[trusted_relayer]` but imposes no constraint linking `fee_recipient` to the caller's identity:

```rust
pub fn sign_transfer(
    &mut self,
    transfer_id: TransferId,
    fee_recipient: Option<AccountId>,   // fully caller-controlled
    fee: &Option<Fee>,
) -> Promise {
```

The caller-supplied `fee_recipient` is embedded verbatim into `TransferMessagePayload` and sent to the MPC signer:

```rust
let transfer_payload = TransferMessagePayload {
    ...
    fee_recipient,   // L498 — no check against env::predecessor_account_id()
    ...
};
```

After a successful MPC signing, `sign_transfer_callback` only removes the transfer when the fee is zero; for non-zero fees the `TransferMessage` remains in `pending_transfers`, keeping the window open for competing calls:

```rust
if let Ok(signature) = call_result {
    if fee.is_zero() {
        self.remove_transfer_message(message_payload.transfer_id);
    }
```

The signed payload permanently encodes `fee_recipient` as the sole account that can later call `claim_fee`. In `claim_fee_callback` the only identity check is:

```rust
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
```

Because the MPC network signs whatever payload it receives, two competing trusted relayers can each obtain a valid MPC signature for the same `transfer_id` but with different `fee_recipient` values. Whoever submits their signed payload to the destination chain first wins the fee; the other relayer's work yields nothing.

## Impact Explanation
This is a concrete instance of **fee mis-accounting that changes relayer balances**, which is an explicitly listed Critical impact. The attacker — a registered trusted relayer — can redirect 100 % of the bridge fee for any pending transfer to their own account. The legitimate relayer who monitored the source chain, paid gas, and initiated the transfer receives zero compensation. Repeated across many transfers this undermines the economic incentive model of the bridge and constitutes direct, repeatable theft of protocol-designated fee revenue.

## Likelihood Explanation
The precondition is registration as a trusted relayer (staking ≥ 1 000 NEAR plus a waiting period). Once that threshold is met the attack is trivially repeatable: all pending transfers are publicly readable from contract state via `pending_transfers`; no mempool monitoring is required. The attacker simply polls `pending_transfers`, calls `sign_transfer` with `fee_recipient` set to their own account, submits the MPC-signed payload to the destination chain, and calls `claim_fee`. The attack window for each transfer remains open until `claim_fee` is successfully executed, giving the attacker ample time to race. "Relayer flows" are explicitly listed as a valid trigger path in the scope rules.

## Recommendation
Bind `fee_recipient` to the caller's identity inside `sign_transfer`. Replace the free parameter with the caller's address:

```rust
let fee_recipient = Some(env::predecessor_account_id());
```

Or, if flexibility is intentionally desired, add a hard guard:

```rust
require!(
    fee_recipient.as_ref() == Some(&env::predecessor_account_id()),
    "fee_recipient must equal caller"
);
```

This ensures only the relayer who actually calls `sign_transfer` can designate themselves as the beneficiary, eliminating the race condition entirely.

## Proof of Concept
1. User calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer`, creating a `TransferMessage` with `fee = 1000` stored in `pending_transfers` under `transfer_id = T`.
2. Legitimate Relayer A observes `T` and calls `sign_transfer(T, fee_recipient=Some(A), fee)`. The MPC network begins signing a payload with `fee_recipient=A`.
3. Malicious Trusted Relayer B (also registered) observes `T` on-chain and calls `sign_transfer(T, fee_recipient=Some(B), fee)`. The MPC network signs a second payload with `fee_recipient=B`. Because `fee.is_zero()` is false, `remove_transfer_message` is not called after either signing; both calls succeed.
4. B submits the MPC-signed payload (with `fee_recipient=B`) to the destination chain (EVM/Solana/etc.) before A, completing the transfer finalization with B encoded as fee recipient.
5. B calls `claim_fee` on NEAR with a proof of the destination-chain finalization. `claim_fee_callback` verifies `fee_recipient(=B) == predecessor_account_id(=B)` ✓ and transfers the 1 000-token fee to B.
6. A's subsequent `claim_fee` attempt fails because `remove_transfer_message` already ran, or because the destination-chain proof already records B as fee recipient — A earns nothing despite having done the legitimate bridging work.

**Minimal local test plan**: Deploy the contract on NEAR sandbox, register two trusted relayers A and B, create a transfer with non-zero fee, have both call `sign_transfer` with their respective accounts as `fee_recipient`, submit B's signed payload to a mock destination-chain prover, call `claim_fee` as B, and assert B receives the fee while A's balance is unchanged.