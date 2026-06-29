The code confirms the claim. Let me verify the `apply_for_trusted_relayer` mechanism to assess whether the trusted relayer precondition is permissionless or privileged.

Audit Report

## Title
Trusted Relayer Can Obtain Multiple MPC Signatures for the Same Non-Zero-Fee Transfer with Different Fee Recipients, Enabling Fee Theft — (`near/omni-bridge/src/lib.rs`)

## Summary

`sign_transfer` submits a `TransferMessagePayload` containing a caller-supplied `fee_recipient` to the MPC signer without locking or removing the transfer from `pending_transfers`. `sign_transfer_callback` only removes the transfer when `fee.is_zero()`. A trusted relayer can therefore call `sign_transfer` repeatedly for the same `transfer_id` with different `fee_recipient` values, obtaining multiple distinct valid MPC signatures and choosing which one to submit to the destination chain — redirecting the fee to an arbitrary account.

## Finding Description

In `sign_transfer` (lines 447–521), the function reads the transfer via `get_transfer_message` without acquiring any lock or removing it from storage, builds a `TransferMessagePayload` embedding the caller-supplied `fee_recipient`, hashes it, and dispatches it to the MPC signer as an async cross-contract call. No "signing in progress" flag is set and the transfer entry is not removed before the async call.

In `sign_transfer_callback` (lines 648–668), the transfer is only removed when `fee.is_zero()`:

```rust
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
```

For any transfer with a non-zero fee, the entry persists in `pending_transfers` after a successful signing. A trusted relayer can call `sign_transfer(T, Some("attacker.near"), None)` immediately after (or instead of) `sign_transfer(T, Some("relayer.near"), None)`. Both calls succeed; the MPC signs two distinct payloads for the same `transfer_id` differing only in `fee_recipient`. The attacker then submits the signature with `fee_recipient = attacker.near` to the destination chain. The destination chain's nonce prevents double-finalization, but the attacker controls which signature is submitted.

The trusted relayer role is obtained permissionlessly via `apply_for_trusted_relayer` with a NEAR stake deposit and a waiting period — it is not an admin-controlled grant. The rules explicitly include "relayer flows" as a valid attack vector.

## Impact Explanation

This is a concrete fee mis-accounting impact: the user's fee escrow on NEAR is consumed correctly, but the fee on the destination chain is paid to an unauthorized recipient chosen by the attacker. This matches the allowed critical impact class: "Balance manipulation, escrow mis-accounting, fee mis-accounting… that changes user or protocol balances." It also constitutes an MPC-related flaw: the MPC is caused to sign multiple distinct payloads for the same logical transfer, violating the invariant that each transfer maps to exactly one signed payload.

## Likelihood Explanation

Preconditions: (1) a non-zero fee transfer (standard in production), (2) a trusted relayer (obtained permissionlessly by staking). The attack requires two sequential `sign_transfer` calls — no race condition, no front-running, no special timing. Any trusted relayer who turns malicious or whose key is compromised can execute this deterministically. The attacker controls both signing calls and the submission to the destination chain.

## Recommendation

Before dispatching the MPC signing request, atomically mark the transfer as "signing in progress" (e.g., add a `signed: bool` or `fee_recipient: Option<AccountId>` field to `TransferMessageStorage`) and reject subsequent `sign_transfer` calls for the same `transfer_id` if the flag is set. Alternatively, remove the transfer from `pending_transfers` before the MPC call and re-insert it only if the MPC call fails — mirroring the pattern used in `submit_transfer_to_utxo_chain_connector` (`near/omni-bridge/src/btc.rs`, line 84) which calls `remove_transfer_message` before the external call.

## Proof of Concept

```
1. Deploy bridge; configure token, MPC mock, and relayer staking (stake_required=1, waiting_period_ns=0).
2. Attacker calls apply_for_trusted_relayer with sufficient stake → becomes trusted relayer.
3. User calls ft_transfer_call → init_transfer with fee = {fee: 100, native_fee: 0}.
   → transfer_id T stored in pending_transfers.
4. Attacker calls sign_transfer(T, Some("relayer.near"), None).
   → MPC signs payload_A = keccak256({..., fee_recipient: "relayer.near"})
   → sign_transfer_callback: fee != 0 → transfer NOT removed.
5. Attacker calls sign_transfer(T, Some("attacker.near"), None).
   → MPC signs payload_B = keccak256({..., fee_recipient: "attacker.near"})
   → sign_transfer_callback: fee != 0 → transfer still NOT removed.
6. Assert: two SignTransferEvents exist for the same transfer_id with different
   fee_recipient values and different signatures — both cryptographically valid.
7. Attacker submits signature_B to destination chain → fee paid to "attacker.near".
```

Root cause confirmed at:
- `sign_transfer` line 453: reads transfer without locking
- `sign_transfer_callback` lines 656–658: only removes when fee is zero