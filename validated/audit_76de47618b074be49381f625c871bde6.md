Looking at the actual code to validate each claim.

Audit Report

## Title
`sign_transfer` Allows Multiple Valid MPC Signatures Per Transfer via Missing Pre-Signing Lock - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`sign_transfer` reads the pending transfer via a read-only `get_transfer_message` call and immediately dispatches the async MPC signing cross-contract call without removing or locking the `pending_transfers` entry. Because NEAR processes multiple transactions within the same block before any callback receipt fires, a trusted relayer can submit two `sign_transfer` calls for the same `transfer_id` in the same block with different `fee_recipient` values, causing the MPC signer to produce two independent, valid signatures. The attacker submits their signature to the destination chain first, stealing the fee that should have gone to the legitimate relayer.

## Finding Description

`get_transfer_message` is a `&self` (immutable) read that never modifies `pending_transfers`:

```rust
pub fn get_transfer_message(&self, transfer_id: TransferId) -> TransferMessage {
    self.pending_transfers
        .get(&transfer_id)
        ...
}
```

`sign_transfer` calls it and immediately enqueues the MPC signing receipt with no removal or sentinel write:

```rust
let transfer_message = self.get_transfer_message(transfer_id);
// ... validation only reads transfer_message fields ...
ext_signer::ext(self.mpc_signer.clone())
    .sign(SignRequest { payload, ... })
    .then(Self::ext(...).sign_transfer_callback(...))
```

`sign_transfer_callback` only removes the entry when `fee.is_zero()`:

```rust
if let Ok(signature) = call_result {
    if fee.is_zero() {
        self.remove_transfer_message(message_payload.transfer_id);
    }
    env::log_str(&OmniBridgeEvent::SignTransferEvent { signature, message_payload }.to_log_string());
}
```

For non-zero fee transfers the entry is never removed by `sign_transfer_callback` at all — it persists in `pending_transfers` until `claim_fee_callback` calls `self.remove_transfer_message(fin_transfer.transfer_id)`. This means unlimited re-signing is possible at any time for non-zero fee transfers.

`fee_recipient` is a fully caller-supplied parameter embedded verbatim into the signed `TransferMessagePayload`:

```rust
pub fn sign_transfer(
    &mut self,
    transfer_id: TransferId,
    fee_recipient: Option<AccountId>,   // caller-controlled
    fee: &Option<Fee>,
) -> Promise {
    ...
    let transfer_payload = TransferMessagePayload {
        ...
        fee_recipient,   // embedded directly into the signed payload
        ...
    };
```

The `fee_recipient` field is part of the borsh-encoded, keccak-hashed payload that the MPC signer signs, and it is included verbatim in the `FinTransfer` event emitted by every destination chain (EVM `OmniBridge.sol` line 40, Starknet `bridge_types.cairo` line 55, Solana `finalize_transfer.rs` line 15). On NEAR, `claim_fee_callback` enforces `fee_recipient == predecessor_account_id`, so whoever controls the `fee_recipient` in the accepted signature controls who receives the fee.

**Exploit flow:**

Block N:
- TX-A: trusted relayer calls `sign_transfer(T, fee_recipient=ATTACKER, fee=F)` → `get_transfer_message(T)` succeeds (entry present) → enqueues MPC signing receipt R-A.
- TX-B: trusted relayer calls `sign_transfer(T, fee_recipient=LEGITIMATE, fee=F)` → `get_transfer_message(T)` succeeds (entry still present; TX-A did not remove it) → enqueues MPC signing receipt R-B.

Block N+1:
- R-A fires → `sign_transfer_callback`: `fee != 0`, entry NOT removed; emits `SignTransferEvent(sig=S-A, fee_recipient=ATTACKER)`.
- R-B fires → `sign_transfer_callback`: `fee != 0`, entry NOT removed; emits `SignTransferEvent(sig=S-B, fee_recipient=LEGITIMATE)`.

Attacker submits `(payload-A, S-A)` to destination chain → nonce consumed, `FinTransfer` event records `fee_recipient=ATTACKER`. Attacker calls `claim_fee` on NEAR with proof of that event → fee credited to attacker. Signature S-B is now useless (nonce already consumed on destination chain).

The destination chain's nonce guard (`completedTransfers[payload.destinationNonce] = true` in EVM `OmniBridge.sol` lines 283–287; `_set_transfer_finalised` in Starknet `omni_bridge.cairo` lines 247–250) prevents double-spending of the principal, but it does not prevent the attacker from racing to submit the attacker-favoring signature first and thereby stealing the fee.

## Impact Explanation

This is a concrete **fee mis-accounting** impact: a trusted relayer can steal 100% of the bridging fee from the legitimate relayer for any non-zero-fee transfer. The fee is real token value paid by the user and held in escrow on NEAR until `claim_fee` is called. By producing two valid MPC signatures with different `fee_recipient` values and submitting the attacker-favoring one to the destination chain first, the attacker permanently redirects the fee to themselves. The legitimate relayer's signature is rendered worthless by the destination chain's nonce guard. This matches the allowed Critical impact: "fee mis-accounting… that changes user or protocol balances."

## Likelihood Explanation

Any account that stakes the required amount (default 1,000 NEAR) and waits the waiting period (default 7 days) becomes a trusted relayer and can call `sign_transfer`. Submitting two transactions in the same NEAR block is a standard operation requiring no special tooling, no validator collusion, no front-running, and no external dependency failure. The attack is deterministic and repeatable for every non-zero-fee transfer that passes through the bridge.

## Recommendation

Remove the transfer from `pending_transfers` (or insert a "signing-in-progress" sentinel) **before** dispatching the MPC cross-contract call, mirroring the atomic insert-or-panic pattern used in `add_fin_transfer`. On MPC callback failure, re-insert the transfer so that legitimate re-signing remains possible. The UTXO path in `submit_transfer_to_utxo_chain_connector` already demonstrates the correct pattern: it calls `self.remove_transfer_message(transfer_id)` before the async call and re-inserts in the failure callback.

## Proof of Concept

**Minimal private-testnet transaction sequence:**

1. Deploy the bridge contract and MPC mock signer on a local NEAR sandbox.
2. Register two accounts as trusted relayers (stake ≥ 1,000 NEAR, wait past the activation period).
3. Initiate a transfer with a non-zero fee via `ft_transfer_call` → `init_transfer`. Record `transfer_id=T` and `fee=F`.
4. In the same block, submit:
   - TX-A: `relayer_attacker.sign_transfer(T, fee_recipient="attacker.near", fee=F)`
   - TX-B: `relayer_attacker.sign_transfer(T, fee_recipient="legitimate.near", fee=F)`
5. Observe that both transactions succeed (neither panics) and both `sign_transfer_callback` invocations emit a `SignTransferEvent` with a valid MPC signature.
6. Submit the attacker-favoring `(payload-A, S-A)` to the destination chain mock; verify `FinTransfer` records `fee_recipient="attacker.near"`.
7. Call `claim_fee` from `attacker.near` with the proof; verify the fee is credited to the attacker.
8. Attempt `claim_fee` from `legitimate.near` with proof of S-B; verify it fails because the destination nonce is already consumed.