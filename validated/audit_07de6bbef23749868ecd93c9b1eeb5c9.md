Audit Report

## Title
Unvalidated `fee_recipient` in `sign_transfer` Allows Any Trusted Relayer to Steal Relayer Fees - (File: near/omni-bridge/src/lib.rs)

## Summary

`sign_transfer` accepts a caller-supplied `fee_recipient: Option<AccountId>` parameter with no check that it equals `env::predecessor_account_id()` or any stored value. Any active trusted relayer can call `sign_transfer` on any pending non-zero-fee transfer, embed an arbitrary `fee_recipient` into the MPC-signed payload, submit that signature to the destination chain, and then call `claim_fee` on NEAR to collect the full relayer fee — diverting it from the legitimate relayer who was meant to service the transfer.

## Finding Description

In `near/omni-bridge/src/lib.rs`, `sign_transfer` is gated by `#[trusted_relayer]` and accepts three caller-supplied arguments: `transfer_id`, `fee_recipient: Option<AccountId>`, and `fee: &Option<Fee>`.

The only validation performed is on the `fee` amount:

```rust
if let Some(fee) = &fee {
    require!(
        &transfer_message.fee == fee,
        BridgeError::InvalidFee.as_ref()
    );
}
```

There is no check that `fee_recipient` equals `env::predecessor_account_id()`. The value is taken verbatim and embedded into the `TransferMessagePayload` sent to the MPC signer:

```rust
let transfer_payload = TransferMessagePayload {
    ...
    fee_recipient,   // ← attacker-controlled
    ...
};
```

In `sign_transfer_callback`, the transfer message is only removed when `fee.is_zero()`. For non-zero-fee transfers it remains in storage, so multiple relayers can call `sign_transfer` on the same transfer:

```rust
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
```

In `claim_fee_callback`, the contract checks that the `fee_recipient` embedded in the on-chain proof matches the caller:

```rust
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
```

Because the attacker embedded their own account as `fee_recipient` at signing time, this check is trivially satisfied. The MPC signature over the full borsh-encoded payload (including `fee_recipient`) is verified by `OmniBridge.sol`'s `finTransfer`, which accepts it as valid since the MPC did sign it.

## Impact Explanation

This is a concrete fee mis-accounting impact: the relayer fee — which is part of the user's locked/burned tokens — is permanently diverted to the attacker. The user's transfer completes correctly (recipient and amount come from the stored transfer message), but the legitimate relayer receives nothing. This matches the Critical allowed impact: "fee mis-accounting... that changes user or protocol balances."

## Likelihood Explanation

Becoming a trusted relayer is permissionless: any account can call `apply_for_trusted_relayer` with the required stake deposit and is automatically promoted after the waiting period elapses, with no admin approval required. An economically motivated actor can stake, become a trusted relayer, and systematically call `sign_transfer` on every pending non-zero-fee transfer with their own account as `fee_recipient`, capturing all relayer fees across the bridge. The attack is fully on-chain, requires no off-chain coordination, and is repeatable at scale.

## Recommendation

Replace the caller-supplied `fee_recipient` parameter with `env::predecessor_account_id()` inside `sign_transfer`, or add an explicit binding check before constructing the payload:

```rust
if let Some(ref recipient) = fee_recipient {
    require!(
        recipient == &env::predecessor_account_id(),
        BridgeError::InvalidFeeRecipient.as_ref()
    );
}
```

This ensures the MPC only ever signs payloads where `fee_recipient` is the relayer who actually called `sign_transfer`.

## Proof of Concept

```
1. Legitimate relayer R1 observes TransferMessage {transfer_id: T, fee: 100, ...} on NEAR.
2. Malicious trusted relayer R2 calls:
       sign_transfer(T, Some("r2.near"), Some(Fee{fee:100,...}))
   before R1 can act (or concurrently — the transfer message persists for non-zero fees).
3. MPC signs payload: {transfer_id:T, recipient:<user>, fee_recipient:"r2.near", amount:X, ...}
4. R2 submits the signed payload to OmniBridge.sol via finTransfer().
   - completedTransfers[destinationNonce] = true  (nonce consumed)
   - Tokens released to the user's recipient address ✓
   - FinTransfer event emitted with fee_recipient="r2.near"
5. R2 generates an EVM Merkle proof of the FinTransfer event.
6. R2 calls claim_fee on NEAR with this proof.
   - claim_fee_callback: fee_recipient == "r2.near" == predecessor_account_id ✓
   - R2 receives 100 tokens.
7. R1 attempts claim_fee — the transfer message has been removed (step 6 calls
   remove_transfer_message), so R1's call panics. The fee is permanently diverted to R2.

Reproducible as a local integration test: set up two trusted relayer accounts,
have R2 call sign_transfer with fee_recipient=R2 on a transfer initiated by a user,
submit the mock-signed payload via the mock prover, call claim_fee as R2, and assert
R2 receives the fee while R1 receives nothing.
```